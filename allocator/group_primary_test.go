package allocator

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// TestNewTopicPrimariesSpread is the regression test for the symptom which
// motivated balance groups: the primaries of a topic created in one shot all
// land on whichever Member's suffix sorts first.
func TestNewTopicPrimariesSpread(t *testing.T) {
	// With balancing disabled, every primary piles onto member-A1. This is a
	// characterization of today's behavior, not an endorsement of it: Slot 0
	// follows the (zone, suffix) order that desired Assignments were solved in.
	t.Run("disabled", func(t *testing.T) {
		var ctx, client, ks = testSetup(t)
		require.NoError(t, insert(ctx, client, newTopicFixture(6, 2)...))
		serveUntilIdle(t, ctx, client, ks, "")

		// member-B replicates all six partitions and is primary for none:
		// Slot 0 follows the (zone, suffix) order desired Assignments were
		// solved in, so it never leaves the first zone.
		require.Equal(t, map[string]int{"member-A1": 4, "member-A2": 2},
			primaryCounts(t, ctx, client, "topic-a/"))
	})

	// Enabled, the same fixture spreads primaries evenly across the Members
	// which replicate the topic -- with no primary ever handed off, since each
	// partition's Slot 0 is chosen as it is first assigned.
	t.Run("enabled", func(t *testing.T) {
		var ctx, client, ks = testSetup(t)
		require.NoError(t, insert(ctx, client, newTopicFixture(6, 2)...))
		serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 4, nil)

		require.Equal(t, map[string]int{"member-A1": 2, "member-A2": 2, "member-B": 2},
			primaryCounts(t, ctx, client, "topic-a/"))
	})
}

// TestPrimaryRebalanceCorrectsExistingSkew settles a cluster with balancing
// disabled -- which is what produces the skew -- and then enables it over that
// already-settled state, verifying primaries are redistributed while replica
// membership is left completely alone.
func TestPrimaryRebalanceCorrectsExistingSkew(t *testing.T) {
	var ctx, client, ks = testSetup(t)
	require.NoError(t, insert(ctx, client, newTopicFixture(6, 2)...))

	serveUntilIdle(t, ctx, client, ks, "")

	var before = replicaSets(t, ctx, client)
	require.Equal(t, map[string]int{"member-A1": 4, "member-A2": 2},
		primaryCounts(t, ctx, client, "topic-a/"))

	// Enabling balancing must now hand off primaries, since no new Assignment
	// is being created for constrainAddPrimary to choose among.
	serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 4, nil)

	require.Equal(t, map[string]int{"member-A1": 2, "member-A2": 2, "member-B": 2},
		primaryCounts(t, ctx, client, "topic-a/"))
	require.Equal(t, before, replicaSets(t, ctx, client))
}

// TestPrimaryRebalanceMultiHop covers the topology where no single handoff
// improves balance, and only a rotation across two partitions does. Member A is
// primary for two partitions it shares with B, and B is primary for one it
// shares with C: counts are 2/1/0, and every one-swap rule either refuses to
// act (a strict rule sees 2 > 1+1 is false) or oscillates A<->B forever.
func TestPrimaryRebalanceMultiHop(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,
		"/root/members/zone-c#mC", `{"R": 20}`,

		"/root/items/g/i1", `{"R": 2, "G": "g"}`,
		"/root/items/g/i2", `{"R": 2, "G": "g"}`,
		"/root/items/g/i3", `{"R": 2, "G": "g"}`,

		"/root/assign/g/i1#zone-a#mA#0", `consistent`,
		"/root/assign/g/i1#zone-b#mB#1", `consistent`,
		"/root/assign/g/i2#zone-a#mA#0", `consistent`,
		"/root/assign/g/i2#zone-b#mB#1", `consistent`,
		"/root/assign/g/i3#zone-b#mB#0", `consistent`,
		"/root/assign/g/i3#zone-c#mC#1", `consistent`,
	))
	require.Equal(t, map[string]int{"mA": 2, "mB": 1}, primaryCounts(t, ctx, client, "g/"))

	serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 4, nil)

	require.Equal(t, map[string]int{"mA": 1, "mB": 1, "mC": 1},
		primaryCounts(t, ctx, client, "g/"))
}

// TestPrimaryRebalanceStopsWhenUnimprovable covers a group whose skew cannot be
// corrected at all, because the under-loaded Member replicates none of it. The
// allocator must recognize this and go idle rather than churn.
func TestPrimaryRebalanceStopsWhenUnimprovable(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,

		// Both partitions are replicated only by mA, which must therefore be
		// primary for both. mB holds none of the group.
		"/root/items/g/i1", `{"R": 1, "G": "g"}`,
		"/root/items/g/i2", `{"R": 1, "G": "g"}`,
		"/root/items/other", `{"R": 1}`,

		"/root/assign/g/i1#zone-a#mA#0", `consistent`,
		"/root/assign/g/i2#zone-a#mA#0", `consistent`,
		"/root/assign/other#zone-b#mB#0", `consistent`,
	))

	// Terminating at all is the assertion: an oscillating rule never goes idle.
	serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 4, nil)

	require.Equal(t, map[string]int{"mA": 2}, primaryCounts(t, ctx, client, "g/"))
}

// TestPrimaryNotHandedToInconsistentReplica verifies that a replica which has
// not caught up is never promoted, even when it would improve balance.
func TestPrimaryNotHandedToInconsistentReplica(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,

		"/root/items/g/i1", `{"R": 2, "G": "g"}`,
		"/root/items/g/i2", `{"R": 2, "G": "g"}`,

		"/root/assign/g/i1#zone-a#mA#0", `consistent`,
		"/root/assign/g/i1#zone-b#mB#1", ``, // Not consistent.
		"/root/assign/g/i2#zone-a#mA#0", `consistent`,
		"/root/assign/g/i2#zone-b#mB#1", ``, // Not consistent.
	))

	// "never" leaves assignments inconsistent for the life of the test.
	serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "never", 4, nil)

	require.Equal(t, map[string]int{"mA": 2}, primaryCounts(t, ctx, client, "g/"))
}

// TestPrimaryRebalanceIsDeterministic verifies the handoffs proposed for a
// fixed State are a pure function of it, with no dependence on map iteration
// or solver internals.
func TestPrimaryRebalanceIsDeterministic(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	var fixture = []string{
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,
		"/root/members/zone-c#mC", `{"R": 20}`,
	}
	for i := 0; i != 9; i++ {
		var partition = fmt.Sprintf("g/part-%03d", i)
		fixture = append(fixture,
			"/root/items/"+partition, `{"R": 3, "G": "g"}`,
			"/root/assign/"+partition+"#zone-a#mA#0", `consistent`,
			"/root/assign/"+partition+"#zone-b#mB#1", `consistent`,
			"/root/assign/"+partition+"#zone-c#mC#2", `consistent`,
		)
	}
	require.NoError(t, insert(ctx, client, fixture...))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "mA"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	var first = rebalanceGroupPrimaries(state, 4)
	require.Len(t, first, 4)

	for i := 0; i != 8; i++ {
		require.Equal(t, first, rebalanceGroupPrimaries(state, 4))
	}
}

// TestPrimaryBalanceUnderMemberChurn drives rolling Member replacement with
// balancing enabled, asserting on every round -- not merely at idle -- that no
// Item ever has two primary Assignments.
//
// This is the regression test for handing off a primary as two independent
// operations: a promotion issued without its matching demotion leaves two
// Slot 0 keys, which readers resolve to whichever sorts last while both Members
// believe they are primary. Member churn is what exposes it, because it is when
// an Item is gaining or losing replicas at the same time as a handoff.
func TestPrimaryBalanceUnderMemberChurn(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	var fixture = []string{
		"/root/members/zone-a#m-a1", `{"R": 20}`,
		"/root/members/zone-a#m-a2", `{"R": 20}`,
		"/root/members/zone-b#m-b1", `{"R": 20}`,
		"/root/members/zone-b#m-b2", `{"R": 20}`,
	}
	for _, topic := range []string{"topic-x", "topic-y", "topic-z"} {
		for i := 0; i != 4; i++ {
			fixture = append(fixture,
				fmt.Sprintf("/root/items/%s/part-%03d", topic, i),
				fmt.Sprintf(`{"R": 2, "G": %q}`, topic))
		}
	}
	require.NoError(t, insert(ctx, client, fixture...))

	var verify = func() { requireSinglePrimaryPerItem(t, ctx, client) }
	serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 2, verify)

	// Replace each Member in turn with a differently-suffixed one, as a rolling
	// deployment would, re-converging after each step.
	for i, member := range []string{"zone-a#m-a1", "zone-a#m-a2", "zone-b#m-b1", "zone-b#m-b2"} {
		var _, err = client.Delete(ctx, "/root/members/"+member)
		require.NoError(t, err)

		var zone = strings.Split(member, "#")[0]
		require.NoError(t, insert(ctx, client,
			fmt.Sprintf("/root/members/%s#m-new%d", zone, i), `{"R": 20}`))

		serveUntilIdleWithPrimaryBalance(t, ctx, client, ks, "", 2, verify)
		requireSinglePrimaryPerItem(t, ctx, client)
	}

	// Every group ends within one primary of even across the Members which
	// replicate it. Members replicating none of a group are excluded: they can
	// never hold its primary, and spreading a group's *replicas* more widely is
	// a separate concern this feature deliberately does not touch.
	for _, topic := range []string{"topic-x", "topic-y", "topic-z"} {
		var counts = primaryCounts(t, ctx, client, topic+"/")
		var reach = make(map[string]int)

		for _, a := range readAssignments(t, ctx, client) {
			if strings.HasPrefix(a.ItemID, topic+"/") {
				reach[a.MemberSuffix]++
			}
		}
		var lo, hi = 1 << 30, 0
		for member := range reach {
			lo, hi = min(lo, counts[member]), max(hi, counts[member])
		}
		require.LessOrEqual(t, hi-lo, 1,
			"%s primaries %v are uneven across the members replicating it %v", topic, counts, reach)
	}
}

// TestPrimarySwapBudget verifies no more handoffs are proposed in one round
// than the configured budget allows.
func TestPrimarySwapBudget(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	var fixture = []string{
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,
		"/root/members/zone-c#mC", `{"R": 20}`,
	}
	for i := 0; i != 9; i++ {
		var partition = fmt.Sprintf("g/part-%03d", i)
		fixture = append(fixture,
			"/root/items/"+partition, `{"R": 3, "G": "g"}`,
			"/root/assign/"+partition+"#zone-a#mA#0", `consistent`,
			"/root/assign/"+partition+"#zone-b#mB#1", `consistent`,
			"/root/assign/"+partition+"#zone-c#mC#2", `consistent`,
		)
	}
	require.NoError(t, insert(ctx, client, fixture...))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "mA"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	require.Len(t, rebalanceGroupPrimaries(state, 1), 1)
	require.Len(t, rebalanceGroupPrimaries(state, 3), 3)
	require.Nil(t, rebalanceGroupPrimaries(state, 0), "a zero budget disables balancing")
}

// requireSinglePrimaryPerItem asserts the allocator datamodel invariant that an
// Item has at most one Slot 0 Assignment.
func requireSinglePrimaryPerItem(t *testing.T, ctx context.Context, client *clientv3.Client) {
	var primaries = make(map[string][]string)

	for _, a := range readAssignments(t, ctx, client) {
		if a.Slot == 0 {
			primaries[a.ItemID] = append(primaries[a.ItemID], a.MemberSuffix)
		}
	}
	for itemID, members := range primaries {
		require.Len(t, members, 1, "item %s has multiple primaries: %v", itemID, members)
	}
}

// TestPrimaryCooldownElapsed covers the pacing predicate directly, so the
// interval is exercised without a clock or a sleep.
func TestPrimaryCooldownElapsed(t *testing.T) {
	var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name     string
		now      time.Time
		lastSwap time.Time
		interval time.Duration
		expect   bool
	}{
		{"zero interval never paces", t0, t0, 0, true},
		{"zero lastSwap always elapses", t0, time.Time{}, time.Minute, true},
		{"before the interval", t0.Add(29 * time.Second), t0, 30 * time.Second, false},
		{"exactly at the interval", t0.Add(30 * time.Second), t0, 30 * time.Second, true},
		{"past the interval", t0.Add(31 * time.Second), t0, 30 * time.Second, true},
		{"clock stepped backwards", t0, t0.Add(time.Minute), 30 * time.Second, false},
	} {
		require.Equal(t, tc.expect,
			primaryCooldownElapsed(tc.now, tc.lastSwap, tc.interval), tc.name)
	}
}

// TestPrimarySwapIntervalPacesHandoffs verifies that handoffs are withheld
// until the interval elapses, even though rounds keep firing -- which is the
// whole point, since an applied handoff is itself an Etcd write that wakes the
// next round.
func TestPrimarySwapIntervalPacesHandoffs(t *testing.T) {
	var ctx, client, ks = testSetup(t)
	require.NoError(t, insert(ctx, client, newTopicFixture(6, 2)...))

	// Settle with balancing off, leaving primaries skewed 4/2/0.
	serveUntilIdle(t, ctx, client, ks, "")
	require.Equal(t, map[string]int{"member-A1": 4, "member-A2": 2},
		primaryCounts(t, ctx, client, "topic-a/"))

	// A stub clock which never advances: the first round may hand off, and
	// every round after it is inside the cooldown.
	var clock = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	var swapsFor = func(interval time.Duration) int {
		var before = totalPrimaryMoves(t, ctx, client, "topic-a/")
		serveWithClock(t, ctx, client, ks, "", 1, interval,
			func() time.Time { return clock }, nil)
		return totalPrimaryMoves(t, ctx, client, "topic-a/") - before
	}

	// Budget of one, an interval that never elapses on a frozen clock: exactly
	// one handoff is applied no matter how many rounds run.
	require.Equal(t, 1, swapsFor(time.Hour))

	// Advancing past the interval releases exactly one more.
	clock = clock.Add(time.Hour)
	require.Equal(t, 1, swapsFor(time.Hour))

	// With no interval, the remaining correction completes in one serve.
	require.Equal(t, 0, swapsFor(0))
	require.Equal(t, map[string]int{"member-A1": 2, "member-A2": 2, "member-B": 2},
		primaryCounts(t, ctx, client, "topic-a/"))
}

// TestPrimarySwapAppliedCountArmsCooldown verifies that converge reports only
// the handoffs it actually applied. The count is what arms the pacing cooldown,
// so a proposal which buildSwapPrimaryOps declines must not consume the
// interval -- otherwise a permanently-blocked Item would idle the mechanism.
func TestPrimarySwapAppliedCountArmsCooldown(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/members/zone-a#mA", `{"R": 20}`,
		"/root/members/zone-b#mB", `{"R": 20}`,
		"/root/members/zone-c#mC", `{"R": 20}`,

		"/root/items/g/i1", `{"R": 2, "G": "g"}`,
		"/root/assign/g/i1#zone-a#mA#0", `consistent`,
		"/root/assign/g/i1#zone-b#mB#1", `consistent`,
	))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "mA"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	// A desired state matching the current one, so nothing but a handoff can
	// be emitted.
	var desired = []Assignment{
		{ItemID: "g/i1", MemberZone: "zone-a", MemberSuffix: "mA"},
		{ItemID: "g/i1", MemberZone: "zone-b", MemberSuffix: "mB"},
	}

	// mC does not replicate the Item, so the handoff cannot be applied.
	var txn mockTxnBuilder
	var applied, err = converge(&txn, state, desired, true,
		map[string]memberID{"g/i1": {zone: "zone-c", suffix: "mC"}})

	require.NoError(t, err)
	require.Zero(t, applied, "a declined handoff must not arm the cooldown")
	require.Empty(t, txn.ops)

	// mB does replicate it, consistently, so this one is applied.
	txn = mockTxnBuilder{}
	applied, err = converge(&txn, state, desired, true,
		map[string]memberID{"g/i1": {zone: "zone-b", suffix: "mB"}})

	require.NoError(t, err)
	require.Equal(t, 1, applied)

	// The exchange is one transaction over four distinct keys: neither key is
	// both put and deleted, which is what lets it be atomic.
	require.Equal(t, []clientv3.Op{
		clientv3.OpDelete("/root/assign/g/i1#zone-a#mA#0"),
		clientv3.OpDelete("/root/assign/g/i1#zone-b#mB#1"),
		clientv3.OpPut("/root/assign/g/i1#zone-a#mA#1", "consistent"),
		clientv3.OpPut("/root/assign/g/i1#zone-b#mB#0", "consistent"),
	}, txn.ops)
}

// totalPrimaryMoves counts primaries held by Members which the unbalanced
// fixture never assigns them to, giving a monotonic measure of how many
// handoffs have been applied so far.
func totalPrimaryMoves(t *testing.T, ctx context.Context, client *clientv3.Client, itemPrefix string) int {
	return primaryCounts(t, ctx, client, itemPrefix)["member-B"]
}

// newTopicFixture returns keys and values declaring |partitions| partitions of
// "topic-a" at replication |r|, plus three Members across two zones.
func newTopicFixture(partitions, r int) []string {
	var out = []string{
		"/root/members/zone-a#member-A1", `{"R": 20}`,
		"/root/members/zone-a#member-A2", `{"R": 20}`,
		"/root/members/zone-b#member-B", `{"R": 20}`,
	}
	for i := 0; i != partitions; i++ {
		out = append(out,
			fmt.Sprintf("/root/items/topic-a/part-%03d", i),
			fmt.Sprintf(`{"R": %d, "G": "topic-a"}`, r))
	}
	return out
}

// primaryCounts returns the number of primary (Slot 0) Assignments held by
// each Member suffix, over Items whose ID has the given prefix. It reads Etcd
// directly, so it may be called before or after an allocator runs. Members
// holding none are omitted.
func primaryCounts(t *testing.T, ctx context.Context, client *clientv3.Client, itemPrefix string) map[string]int {
	var out = make(map[string]int)

	for _, a := range readAssignments(t, ctx, client) {
		if a.Slot == 0 && strings.HasPrefix(a.ItemID, itemPrefix) {
			out[a.MemberSuffix]++
		}
	}
	return out
}

// replicaSets returns the sorted Member suffixes replicating each Item,
// independent of Slot -- so it is unchanged by a primary handoff.
func replicaSets(t *testing.T, ctx context.Context, client *clientv3.Client) map[string][]string {
	var out = make(map[string][]string)

	for _, a := range readAssignments(t, ctx, client) {
		out[a.ItemID] = append(out[a.ItemID], a.MemberSuffix)
	}
	for _, v := range out {
		slices.Sort(v)
	}
	return out
}

// readAssignments parses every Assignment key under the test root. Item IDs may
// contain '/' but never '#', which is what makes the split unambiguous.
func readAssignments(t *testing.T, ctx context.Context, client *clientv3.Client) []Assignment {
	var resp, err = client.Get(ctx, "/root"+AssignmentsPrefix, clientv3.WithPrefix())
	require.NoError(t, err)

	var out []Assignment
	for _, kv := range resp.Kvs {
		var parts = strings.Split(strings.TrimPrefix(string(kv.Key), "/root"+AssignmentsPrefix), "#")
		require.Len(t, parts, 4, string(kv.Key))

		var slot int
		_, err = fmt.Sscanf(parts[3], "%d", &slot)
		require.NoError(t, err)

		out = append(out, Assignment{
			ItemID:       parts[0],
			MemberZone:   parts[1],
			MemberSuffix: parts[2],
			Slot:         slot,
		})
	}
	return out
}
