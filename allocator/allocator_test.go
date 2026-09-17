package allocator

import (
	"context"
	"fmt"
	"testing"

	epb "go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.gazette.dev/core/allocator/sparse_push_relabel"
	"go.gazette.dev/core/etcdtest"
	gc "gopkg.in/check.v1"
)

type AllocatorSuite struct{}

func (s *AllocatorSuite) TestRemoveDeadAssignments(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()
	buildAllocKeySpaceFixture(c, ctx, client)

	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	var assignments = ks.Prefixed(ks.Root + AssignmentsPrefix)
	var txn mockTxnBuilder

	// Only "item-missing" is actually a dead Assignment in the fixture, but we can
	// still pass all Assignments and verify Cmps and Ops of the resulting
	// transaction (which wouldn't actually succeed, since Items exist).
	c.Check(removeDeadAssignments(&txn, ks, assignments), gc.IsNil)

	// Expect Assignments are grouped by Item. The non-existence of the Item is
	// verified, as well as that each Assignment is unchanged.
	c.Check(txn.cmps, gc.DeepEquals, []clientv3.Cmp{
		clientv3.Compare(clientv3.CreateRevision("/root/items/item-1"), "=", 0),
		modRevisionUnchanged(assignments[0]), // assign/item-1#us-east#foo#1
		modRevisionUnchanged(assignments[1]), // assign/item-1#us-west#baz#0
		clientv3.Compare(clientv3.CreateRevision("/root/items/item-missing"), "=", 0),
		modRevisionUnchanged(assignments[2]), // assign/item-missing#us-west#baz#0
		clientv3.Compare(clientv3.CreateRevision("/root/items/item-two"), "=", 0),
		modRevisionUnchanged(assignments[3]), // assign/item-two#missing#member#2
		modRevisionUnchanged(assignments[4]), // assign/item-two#us-east#bar#0
		modRevisionUnchanged(assignments[5]), // assign/item-two#us-west#baz#1
	})

	c.Check(txn.ops, gc.DeepEquals, []clientv3.Op{
		clientv3.OpDelete("/root/assign/item-1#us-east#foo#1"),
		clientv3.OpDelete("/root/assign/item-1#us-west#baz#0"),
		clientv3.OpDelete("/root/assign/item-missing#us-west#baz#0"),
		clientv3.OpDelete("/root/assign/item-two#missing#member#2"),
		clientv3.OpDelete("/root/assign/item-two#us-east#bar#0"),
		clientv3.OpDelete("/root/assign/item-two#us-west#baz#1"),
	})
}

func (s *AllocatorSuite) TestPrimaryFlowNetworkRebalancesSkewedPrimaries(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()

	for k, v := range map[string]string{
		"/root/items/a-topic/part-00": `{"R": 2}`,
		"/root/items/a-topic/part-01": `{"R": 2}`,
		"/root/items/a-topic/part-02": `{"R": 2}`,
		"/root/items/singleton":       `{"R": 1}`, // Not a multi-Item group: excluded.

		"/root/members/zone#member-0": `{"R": 10}`,
		"/root/members/zone#member-1": `{"R": 10}`,

		// a-topic's primaries (Slot 0) skew heavily towards member-0, though
		// both Members replicate every Item (so any Item could take over).
		"/root/assign/a-topic/part-00#zone#member-0#0": ``,
		"/root/assign/a-topic/part-00#zone#member-1#1": ``,
		"/root/assign/a-topic/part-01#zone#member-0#0": ``,
		"/root/assign/a-topic/part-01#zone#member-1#1": ``,
		"/root/assign/a-topic/part-02#zone#member-0#0": ``,
		"/root/assign/a-topic/part-02#zone#member-1#1": ``,

		"/root/assign/singleton#zone#member-0#0": ``,
	} {
		var _, err = client.Put(ctx, k, v)
		c.Assert(err, gc.IsNil)
	}
	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	var network = newPrimaryFlowNetwork(
		ks.Prefixed(ks.Root+ItemsPrefix),
		ks.Prefixed(ks.Root+AssignmentsPrefix),
	)
	var desired = network.extractPrimaries(sparse_push_relabel.FindMaxFlow(network))

	// Every tracked-group Item is assigned exactly one primary, and the
	// singleton "singleton" Item is untouched by this network entirely.
	c.Check(desired, gc.HasLen, 3)
	_, ok := desired["singleton"]
	c.Check(ok, gc.Equals, false)

	// With 3 Items split across 2 Members, fair share is 2 and 1 -- the
	// most even split actually achievable -- regardless of which specific
	// Member started out over-loaded.
	var counts = summarizeDesiredPrimaries(desired)["a-topic"]
	var lo, hi = 1 << 30, 0
	for _, n := range counts {
		lo, hi = min(lo, n), max(hi, n)
	}
	c.Check(lo, gc.Equals, 1)
	c.Check(hi, gc.Equals, 2)
}

// TestPrimaryFlowNetworkIsStableFixedPoint is a regression test for a bug
// where discharge()'s deterministic Arc-order shift (see push_relabel.go,
// `arcShift = int(nid) % len(arcs)`) silently defeated the PushFront-based
// preference for an Item's current primary whenever an Item's NodeID landed
// on a non-zero shift. Because primaryFlowNetwork is re-solved fresh every
// converge() round from the *current* Assignments, an unstable preference
// caused a genuine 2-cycle in production: each round "corrected" a primary
// departure the shift itself had caused the round before, so the allocator
// never reached an idle state and Allocate() spun forever.
//
// This test re-solves the network many times in a row, each time seeding
// the next solve's "current primary" from the previous solve's output
// (exactly as converge() does across successive rounds against Etcd) and
// asserts the solution never changes after its first stabilization -- ie
// primaryFlowNetwork is a stable fixed point, not an oscillator.
func (s *AllocatorSuite) TestPrimaryFlowNetworkIsStableFixedPoint(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()

	var kv = map[string]string{
		"/root/members/zone-a#member-1": `{"R": 100}`,
		"/root/members/zone-a#member-2": `{"R": 100}`,
		"/root/members/zone-a#member-3": `{"R": 100}`,
		"/root/members/zone-a#member-4": `{"R": 100}`,
		"/root/members/zone-b#member-1": `{"R": 100}`,
		"/root/members/zone-b#member-2": `{"R": 100}`,
		"/root/members/zone-b#member-3": `{"R": 100}`,
		"/root/members/zone-b#member-4": `{"R": 100}`,
	}
	// 16 Items of a single group, each replicated by one zone-a and one
	// zone-b Member, mirroring TestPartitionedItemsBalanceAcrossZonedMembers
	// (whose Item NodeIDs span both even and odd Arc shifts).
	var zoneA, zoneB = []string{"1", "2", "3", "4"}, []string{"1", "2", "3", "4"}
	for i := 0; i != 16; i++ {
		var id = fmt.Sprintf("a-topic/part-%02d", i)
		kv["/root/items/"+id] = `{"R": 2}`
		kv["/root/assign/"+id+"#zone-a#member-"+zoneA[i%len(zoneA)]+"#0"] = ``
		kv["/root/assign/"+id+"#zone-b#member-"+zoneB[i%len(zoneB)]+"#1"] = ``
	}
	for k, v := range kv {
		var _, err = client.Put(ctx, k, v)
		c.Assert(err, gc.IsNil)
	}
	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	var items = ks.Prefixed(ks.Root + ItemsPrefix)
	var assignments = ks.Prefixed(ks.Root + AssignmentsPrefix)

	var last map[string]string
	for round := 0; round != 6; round++ {
		var network = newPrimaryFlowNetwork(items, assignments)
		var next = network.extractPrimaries(sparse_push_relabel.FindMaxFlow(network))
		c.Check(next, gc.HasLen, 16)

		if round > 0 {
			c.Check(next, gc.DeepEquals, last,
				gc.Commentf("primary selection changed on round %d despite unchanged fair-share pressure", round))
		}
		last = next

		// Apply |next| back onto |assignments|' Slots, exactly as
		// constrainReorders would, ahead of the following round's solve.
		for i := range assignments {
			var a = assignmentAt(assignments, i)
			if a.Slot == 0 && next[a.ItemID] != memberKeyOf(a) {
				a.Slot = 1
			} else if a.Slot != 0 && next[a.ItemID] == memberKeyOf(a) {
				a.Slot = 0
			}
			assignments[i].Decoded = a
		}
	}
}

// TestPrimaryFlowNetworkClosesGapUnderLooseCap is a regression test for a
// production observation: 16 Items (R=2) split evenly enough across 3
// Members that "group balance" never warned (membership spread <= 1), yet
// "primary balance" stayed pinned at a 4/6/6 split indefinitely, despite
// the arc-shift stability fix (see TestPrimaryFlowNetworkIsStableFixedPoint)
// already being deployed.
//
// The culprit: fair share was computed as a uniform *ceiling* applied to
// every Member (eg ceil(16/3)=6 given to all 3), which sums to 18 -- two
// more than the 16 primaries actually available. That slack meant a
// skewed-but-loose-cap-satisfying arrangement like 4/6/6 was already a
// valid maximum flow the moment the solver considered it, so the "keep
// current primary" stability bias (needed to prevent the oscillation fixed
// above) had no pressure to look further, and the network -- though
// perfectly *stable* -- never closed the gap to a fairer 5/5/6 or 6/5/5.
//
// The fix distributes the exact remainder across Members instead (floor
// share, +1 for only as many Members as the remainder requires), so cap
// sums to precisely 16, forcing genuine redistribution.
func (s *AllocatorSuite) TestPrimaryFlowNetworkClosesGapUnderLooseCap(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()

	var kv = map[string]string{
		"/root/members/zone#member-0": `{"R": 100}`,
		"/root/members/zone#member-1": `{"R": 100}`,
		"/root/members/zone#member-2": `{"R": 100}`,
	}
	// Cycle replica pairs {0,1}, {1,2}, {0,2} across 16 Items, giving a
	// membership spread of just 1 (11/11/10) -- realistic, already-settled
	// group balance -- while deliberately skewing *primaries* to a 4/6/6
	// split that satisfies a loose, uniform ceiling cap of 6 for every
	// Member without any Member ever exceeding it.
	for i := 0; i != 16; i++ {
		var id = fmt.Sprintf("a-topic/part-%02d", i)
		kv["/root/items/"+id] = `{"R": 2}`

		switch i % 3 {
		case 0: // Pair {member-0, member-1}: primary always member-1.
			kv["/root/assign/"+id+"#zone#member-0#1"] = ``
			kv["/root/assign/"+id+"#zone#member-1#0"] = ``
		case 1: // Pair {member-1, member-2}: primary always member-2.
			kv["/root/assign/"+id+"#zone#member-1#1"] = ``
			kv["/root/assign/"+id+"#zone#member-2#0"] = ``
		case 2: // Pair {member-0, member-2}: primary member-0 except once.
			if i == 2 {
				kv["/root/assign/"+id+"#zone#member-0#1"] = ``
				kv["/root/assign/"+id+"#zone#member-2#0"] = ``
			} else {
				kv["/root/assign/"+id+"#zone#member-0#0"] = ``
				kv["/root/assign/"+id+"#zone#member-2#1"] = ``
			}
		}
	}
	for k, v := range kv {
		var _, err = client.Put(ctx, k, v)
		c.Assert(err, gc.IsNil)
	}
	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	var items = ks.Prefixed(ks.Root + ItemsPrefix)
	var assignments = ks.Prefixed(ks.Root + AssignmentsPrefix)

	// Confirm the fixture actually reproduces the reported 4/6/6 split
	// before asking the network to fix it.
	var before = make(map[string]int)
	for i := range assignments {
		var a = assignmentAt(assignments, i)
		if a.Slot == 0 {
			before[memberKeyOf(a)]++
		}
	}
	c.Check(before, gc.DeepEquals, map[string]int{
		"zone#member-0": 4, "zone#member-1": 6, "zone#member-2": 6,
	})

	var network = newPrimaryFlowNetwork(items, assignments)
	var desired = network.extractPrimaries(sparse_push_relabel.FindMaxFlow(network))
	c.Check(desired, gc.HasLen, 16)

	var counts = summarizeDesiredPrimaries(desired)["a-topic"]
	var lo, hi = 1 << 30, 0
	for _, n := range counts {
		lo, hi = min(lo, n), max(hi, n)
	}
	c.Check(hi-lo <= 1, gc.Equals, true,
		gc.Commentf("expected primary spread <= 1, got counts %v", counts))
}

// TestPrimaryFlowNetworkStableUnderReachabilityShortfall is a regression
// test for a third oscillation source, seen in production with 16 Items
// (R=3, one replica per zone) spread across 6 Members in 3 zones. One
// Member (analogous to a recently-scaled zone-mate that hasn't yet
// received its fair share of *replica* membership) structurally replicates
// very few Items, and so can never reach its nominal fair-share cap no
// matter how primaries are chosen -- that's an upstream replica-membership
// concern, not something primary selection can fix. But the *shortfall* it
// leaves behind must land somewhere, and the previous fix (a precise,
// evenly-divided cap per Member) has no further guidance for how to
// redistribute demand that a Member structurally can't absorb: it falls
// back to push/relabel's dynamic, pressure-triggered relaxation to
// *unbounded* capacity, which has no deterministic tie-break for *which*
// of several equally-eligible Members should absorb the overflow --
// producing the same class of round-over-round flapping the earlier arc-
// shift fix addressed, just one layer higher (across Members instead of
// within a single Item's own candidates).
func (s *AllocatorSuite) TestPrimaryFlowNetworkStableUnderReachabilityShortfall(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()

	var kv = map[string]string{
		"/root/members/us-east-1c#tc2rb": `{"R": 100}`,
		"/root/members/us-east-1c#vgmpf": `{"R": 100}`,
		"/root/members/us-east-1d#b52b8": `{"R": 100}`,
		"/root/members/us-east-1d#m956h": `{"R": 100}`,
		"/root/members/us-east-1d#t9wdw": `{"R": 100}`,
		"/root/members/us-east-1e#hbkq2": `{"R": 100}`,
	}
	// One replica per zone (R=3): zone 1c alternates tc2rb/vgmpf, but
	// vgmpf only actually lands on a single Item (i == 15) -- mirroring a
	// Member that structurally can't reach any reasonable fair share.
	// Zone 1d round-robins its three Members evenly. Zone 1e has only one
	// Member (hbkq2), which necessarily replicates every Item.
	var zoneD = []string{"b52b8", "m956h", "t9wdw"}
	for i := 0; i != 16; i++ {
		var id = fmt.Sprintf("records/part-%02d", i)
		kv["/root/items/"+id] = `{"R": 3}`

		var zoneCMember = "tc2rb"
		if i == 15 {
			zoneCMember = "vgmpf"
		}
		// Arbitrary initial primary: whichever zone-1d Member replicates it.
		kv["/root/assign/"+id+"#us-east-1c#"+zoneCMember+"#1"] = ``
		kv["/root/assign/"+id+"#us-east-1d#"+zoneD[i%len(zoneD)]+"#0"] = ``
		kv["/root/assign/"+id+"#us-east-1e#hbkq2#2"] = ``
	}
	for k, v := range kv {
		var _, err = client.Put(ctx, k, v)
		c.Assert(err, gc.IsNil)
	}
	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	var items = ks.Prefixed(ks.Root + ItemsPrefix)
	var assignments = ks.Prefixed(ks.Root + AssignmentsPrefix)

	var last map[string]string
	for round := 0; round != 8; round++ {
		var network = newPrimaryFlowNetwork(items, assignments)
		var next = network.extractPrimaries(sparse_push_relabel.FindMaxFlow(network))
		c.Check(next, gc.HasLen, 16)

		if round > 0 {
			c.Check(next, gc.DeepEquals, last,
				gc.Commentf("primary selection changed on round %d despite unchanged fair-share pressure", round))
		}
		last = next

		for i := range assignments {
			var a = assignmentAt(assignments, i)
			if a.Slot == 0 && next[a.ItemID] != memberKeyOf(a) {
				a.Slot = 1
			} else if a.Slot != 0 && next[a.ItemID] == memberKeyOf(a) {
				a.Slot = 0
			}
			assignments[i].Decoded = a
		}
	}

	var counts = summarizeDesiredPrimaries(last)["records"]
	var lo, hi = 1 << 30, 0
	for _, n := range counts {
		lo, hi = min(lo, n), max(hi, n)
	}
	c.Check(hi-lo <= 2, gc.Equals, true,
		gc.Commentf("expected primary spread <= 2 given vgmpf's structural shortfall, got counts %v", counts))
}

func (s *AllocatorSuite) TestConvergeFixtureCases(c *gc.C) {
	var client, ctx = etcdtest.TestClient(), context.Background()
	defer etcdtest.Cleanup()
	buildAllocKeySpaceFixture(c, ctx, client)

	var ks = NewAllocatorKeySpace("/root", testAllocDecoder{})
	var as = NewObservedState(ks, MemberKey(ks, "us-east", "foo"), isConsistent)
	c.Check(ks.Load(ctx, client, 0), gc.IsNil)

	// Tweak the fixture to associate a lease with Member us-east/foo
	as.Members[1].Raw.Lease = 0xfeedbeef

	// Case 1: desired state matches current state, aside from fix-ups for missing Items / Members.
	var txn mockTxnBuilder
	converge(&txn, as, []Assignment{
		{ItemID: "item-1", MemberZone: "us-east", MemberSuffix: "foo"},
		{ItemID: "item-1", MemberZone: "us-west", MemberSuffix: "baz"},

		{ItemID: "item-two", MemberZone: "us-east", MemberSuffix: "bar"},
		{ItemID: "item-two", MemberZone: "us-west", MemberSuffix: "baz"},
	})

	var expectCmps = []clientv3.Cmp{
		clientv3.Compare(clientv3.CreateRevision("/root/items/item-missing"), "=", 0),
		modRevisionUnchanged(as.Assignments[2]), // assign/item-missing#us-west#baz#0
		modRevisionUnchanged(as.Items[1]),       // items/item-two
		modRevisionUnchanged(as.Assignments[3]), // assign/item-two#missing#member#2
	}
	c.Check(txn.cmps, gc.DeepEquals, expectCmps)
	c.Check(txn.ops, gc.DeepEquals, []clientv3.Op{
		clientv3.OpDelete("/root/assign/item-missing#us-west#baz#0"),
		clientv3.OpDelete("/root/assign/item-two#missing#member#2"),
	})

	// Case 2: desire to flip "foo" and "bar". "bar" is at capacity, "foo" is not:
	// expect an Assignment for "foo" (only) is created.
	txn = mockTxnBuilder{}
	converge(&txn, as, []Assignment{
		{ItemID: "item-1", MemberZone: "us-east", MemberSuffix: "bar"},
		{ItemID: "item-1", MemberZone: "us-west", MemberSuffix: "baz"},

		{ItemID: "item-two", MemberZone: "us-east", MemberSuffix: "foo"},
		{ItemID: "item-two", MemberZone: "us-west", MemberSuffix: "baz"},
	})

	// In addition to the cleanup checks of the previous case,
	// expect Member us-east/foo is also verified as unchanged.
	c.Check(txn.cmps, gc.DeepEquals, append(
		append(expectCmps[:2:2], modRevisionUnchanged(as.Members[1])), expectCmps[2:]...))

	c.Check(txn.ops, gc.DeepEquals, []clientv3.Op{
		clientv3.OpDelete("/root/assign/item-missing#us-west#baz#0"),
		clientv3.OpPut("/root/assign/item-two#us-east#foo#3", "", clientv3.WithLease(0xfeedbeef)),
		clientv3.OpDelete("/root/assign/item-two#missing#member#2"),
	})
}

func (s *AllocatorSuite) TestTxnBatching(c *gc.C) {
	// Cmp and Op fixtures for use in this test.
	var fixedCmp = clientv3.Compare(clientv3.Value("/key-1"), "=", "val-1")
	var testCmp = clientv3.Compare(clientv3.Value("/key-2"), "=", "val-2")
	var testOp = clientv3.OpDelete("/other-key")

	var txnOp clientv3.Op                // Collects last-dispatched OpTxn.
	var txnResp = &clientv3.TxnResponse{ // Returned response fixture.
		Succeeded: true,
		Header:    &epb.ResponseHeader{Revision: 1234},
	}

	var txn = batchedTxn{
		txnDo: func(op clientv3.Op) (*clientv3.TxnResponse, error) {
			var c, o, _ = op.Txn()
			txnOp = clientv3.OpTxn( // Deep-copy |op|.
				append([]clientv3.Cmp(nil), c...),
				append([]clientv3.Op(nil), o...),
				nil)

			return txnResp, nil
		},
		fixedCmps: []clientv3.Cmp{fixedCmp},
	}

	defer func(m int) { maxTxnOps = m }(maxTxnOps) // For this test, fix |maxTxnOps| to 3.
	maxTxnOps = 3

	c.Check(txn.If(testCmp).Then(testOp).Checkpoint(), gc.IsNil) // No flush (2 Cmps, 1 Op).
	c.Check(txn.If(testCmp).Then(testOp).Checkpoint(), gc.IsNil) // No flush (3 Cmps, 2 Ops).

	c.Check(txnOp, gc.DeepEquals, clientv3.Op{})                         // Verify no transaction issued yet.
	c.Check(txn.If(testCmp).Then(testOp, testOp).Checkpoint(), gc.IsNil) // Forces flush (4 Cmps).

	c.Check(txnOp, gc.DeepEquals, clientv3.OpTxn(
		[]clientv3.Cmp{fixedCmp, testCmp, testCmp},
		[]clientv3.Op{testOp, testOp},
		nil,
	))

	c.Check(txn.Then(testOp).Checkpoint(), gc.IsNil)                     // No flush.
	c.Check(txn.If(testCmp).Then(testOp, testOp).Checkpoint(), gc.IsNil) // Flush (4 Ops).

	c.Check(txnOp, gc.DeepEquals, clientv3.OpTxn(
		[]clientv3.Cmp{fixedCmp, testCmp},
		[]clientv3.Op{testOp, testOp, testOp},
		nil,
	))

	// Final commit. Expect it flushes the last checkpoint.
	c.Check(txn.Flush(), gc.IsNil)

	c.Check(txnOp, gc.DeepEquals, clientv3.OpTxn(
		[]clientv3.Cmp{fixedCmp, testCmp},
		[]clientv3.Op{testOp, testOp},
		nil,
	))

	// Empty Checkpoint, then Commit. Expect it's treated as a no-op.
	c.Check(txn.Checkpoint(), gc.IsNil)

	c.Check(txn.Flush(), gc.IsNil)

	// Non-empty commit that fails checks. Expect it's mapped to an error.
	c.Check(txn.Then(testOp).Checkpoint(), gc.IsNil)
	txnResp.Succeeded = false

	c.Check(txn.Flush(), gc.ErrorMatches, "transaction checks did not succeed")
}

var _ = gc.Suite(&AllocatorSuite{})

func Test(t *testing.T) { gc.TestingT(t) }
