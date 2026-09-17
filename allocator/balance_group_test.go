package allocator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBalanceGroupStateBookkeeping verifies the per-group indices and counts
// which State extracts from a KeySpace, over a fixture whose "topic-a" group
// has all three of its primaries piled onto one Member -- the skew this
// feature exists to detect and correct.
func TestBalanceGroupStateBookkeeping(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/items/solo", `{"R": 1}`,
		"/root/items/topic-a/part-000", `{"R": 2, "G": "topic-a"}`,
		"/root/items/topic-a/part-001", `{"R": 2, "G": "topic-a"}`,
		"/root/items/topic-a/part-002", `{"R": 2, "G": "topic-a"}`,
		"/root/items/topic-b/part-000", `{"R": 1, "G": "topic-b"}`,

		"/root/members/zone-a#m1", `{"R": 10}`,
		"/root/members/zone-a#m2", `{"R": 10}`,
		"/root/members/zone-b#m3", `{"R": 10}`,

		"/root/assign/solo#zone-b#m3#0", `consistent`,
		"/root/assign/topic-a/part-000#zone-a#m1#0", `consistent`,
		"/root/assign/topic-a/part-000#zone-b#m3#1", `consistent`,
		"/root/assign/topic-a/part-001#zone-a#m1#0", `consistent`,
		"/root/assign/topic-a/part-001#zone-b#m3#1", `consistent`,
		"/root/assign/topic-a/part-002#zone-a#m1#0", `consistent`,
		"/root/assign/topic-a/part-002#zone-a#m2#1", `consistent`,
		"/root/assign/topic-b/part-000#zone-a#m2#0", `consistent`,
	))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "m1"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	// Groups are indexed densely in order of first appearance among Items,
	// which are themselves in Etcd key order. Index zero is the ungrouped
	// sentinel, and "solo" sorts ahead of both topics.
	require.Equal(t, []string{"", "topic-a", "topic-b"}, state.GroupNames)
	require.Equal(t, []int32{0, 1, 1, 1, 2}, state.ItemGroups)
	require.Equal(t, []int{1, 3, 1}, state.GroupItemCount)

	// Row-major over [group][member], with Members ordered m1, m2, m3.
	require.Equal(t, []int32{
		0, 0, 0, // Ungrouped sentinel is never populated.
		3, 0, 0, // topic-a: every primary is on m1.
		0, 1, 0, // topic-b.
	}, state.GroupPrimaryCount)

	require.Equal(t, []int32{
		0, 0, 0,
		3, 1, 2, // m1 replicates all of topic-a, m2 one, m3 two.
		0, 1, 0,
	}, state.GroupMemberReach)

	// m1 holds 3 of topic-a's primaries and m2 and m3 hold none, though both
	// replicate part of it: a spread of 3, and 3x an even share.
	require.Equal(t, 3, state.MaxGroupPrimarySpread)
	require.Equal(t, 3.0, state.maxGroupPrimaryShare())
}

// TestBalanceGroupAbsentIsInert verifies that Items declaring no group leave
// every group-aware field empty, which is what makes the feature a no-op for
// an unlabeled cluster.
func TestBalanceGroupAbsentIsInert(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/items/item-1", `{"R": 2}`,
		"/root/items/item-2", `{"R": 2}`,

		"/root/members/zone-a#m1", `{"R": 10}`,
		"/root/members/zone-b#m2", `{"R": 10}`,

		"/root/assign/item-1#zone-a#m1#0", `consistent`,
		"/root/assign/item-1#zone-b#m2#1", `consistent`,
		"/root/assign/item-2#zone-a#m1#0", `consistent`,
	))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "m1"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	require.Equal(t, []string{""}, state.GroupNames)
	require.Equal(t, []int32{0, 0}, state.ItemGroups)
	require.Empty(t, state.GroupPrimaryCount)
	require.Empty(t, state.GroupMemberReach)
	require.Equal(t, 0, state.MaxGroupPrimarySpread)
	require.Equal(t, 0.0, state.maxGroupPrimaryShare())

	// Member-wide counts are unaffected by grouping.
	require.Equal(t, []int{2, 1}, state.MemberTotalCount)
	require.Equal(t, []int{2, 0}, state.MemberPrimaryCount)
}

// TestBalanceGroupEmptyValueIsUngrouped verifies an explicitly empty group
// value is treated as no group at all, rather than as a group named "".
func TestBalanceGroupEmptyValueIsUngrouped(t *testing.T) {
	var ctx, client, ks = testSetup(t)

	require.NoError(t, insert(ctx, client,
		"/root/items/item-1", `{"R": 1, "G": ""}`,
		"/root/items/item-2", `{"R": 1, "G": "g"}`,

		"/root/members/zone-a#m1", `{"R": 10}`,
	))

	var state = NewObservedState(ks, MemberKey(ks, "zone-a", "m1"), isConsistent)
	require.NoError(t, ks.Load(ctx, client, 0))

	require.Equal(t, []string{"", "g"}, state.GroupNames)
	require.Equal(t, []int32{0, 1}, state.ItemGroups)
}
