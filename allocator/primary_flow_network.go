package allocator

import (
	"sort"

	pr "go.gazette.dev/core/allocator/sparse_push_relabel"
	"go.gazette.dev/core/keyspace"
)

// primaryFlowNetwork models the selection of a primary (Slot 0) Assignment
// for each Item of a tracked multi-Item group (see itemGroup), independent
// of -- and much smaller than -- the main sparseFlowNetwork which decides
// overall replica membership. Structurally:
//
//	Source -> Item (cap 1) -> Group-Member (cap 1 per current replica) -> Sink
//
// Every Item of a tracked group contributes exactly one unit of source flow,
// which must land on one of the Item's *current* replica Members (an Item's
// replica set is fixed input here: this network only ever chooses *which*
// replica is primary, never *which* Members replicate the Item -- that's the
// main network's job). A Group-Member's arc to the Sink is capacity-bound to
// that Member's fair share of the group's primaries, relaxed under pressure
// so that a maximum flow (one primary per Item) is always achieved, even
// when perfect fair share isn't structurally possible given the specific
// replica pairings in play.
//
// Because replica membership is already fixed and settled by the time this
// network is solved, there's no need for a Zone-Item layer, or for Member
// capacity scaled by overall cluster load: primary selection is purely about
// fairness *within* each group, and is solved as a genuine (if small) max-
// flow rather than a greedy local heuristic, since a single, locally-best
// swap is not always sufficient -- some topologies require a multi-hop
// rotation of primaries across several Items to reach an even distribution.
type primaryFlowNetwork struct {
	// items holds one entry per Item node, in NodeID order.
	items []primaryFlowItem
	// groupMemberCap and groupMemberKey are parallel slices holding, for
	// each Group-Member node (in NodeID order), its fair-share Sink arc
	// capacity and underlying Member key ("zone#suffix").
	groupMemberCap []pr.Rate
	groupMemberKey []string

	firstItemNodeID        pr.NodeID
	firstGroupMemberNodeID pr.NodeID

	scratch [8]pr.Arc
}

// primaryFlowItem holds an Item's ID and its ordered candidate Group-Member
// NodeIDs -- the Group-Member nodes reachable from its current replica
// Members. The first candidate is the Item's current primary, if it has one.
type primaryFlowItem struct {
	itemID     string
	candidates []pr.NodeID
}

// primaryGroupMemberOverflowThreshold mirrors the reasoning of
// groupMemberOverflowThreshold and memberOverflowThreshold in
// sparse_flow_network.go, adapted to this network's shallower structure. A
// Group-Member here sits directly in front of the Sink (Group-Member ->
// Sink), just one hop from its Item (Item -> Group-Member), vs. the main
// network's Member node, which is 3 hops from Item. Following that same
// "-1 per hop away from Item" derivation, a single hop implies a threshold
// of 0: as soon as any pressure at all is observed on a Group-Member (it
// couldn't immediately push its excess to the Sink), we relax its cap,
// favoring a complete assignment (every Item gets a primary) over perfect
// fair share.
const primaryGroupMemberOverflowThreshold = 0

// newPrimaryFlowNetwork builds a *primaryFlowNetwork from |items| and
// |assignments| (both in their natural, State-provided order). Only Items
// belonging to a tracked multi-Item group (2+ Items -- see itemGroup) are
// modeled; primary selection for singleton-group Items is left to the
// simpler, existing per-Item logic in itemState.constrainReorders.
func newPrimaryFlowNetwork(items, assignments keyspace.KeyValues) *primaryFlowNetwork {
	var rawGroupCounts = make(map[string]int)
	for i := range items {
		rawGroupCounts[itemGroup(itemAt(items, i).ID)]++
	}

	type groupInfo struct {
		itemCount int
		members   map[string]bool
		// reachable[k] counts the Items of this group for which Member |k|
		// is a candidate at all (ie currently replicates it), regardless of
		// Slot. It upper-bounds how many of the group's primaries |k| could
		// ever hold, and is used to compute a precise, deterministic fair-
		// share cap per Member -- see groupMemberCaps.
		reachable map[string]int
	}
	var groups = make(map[string]*groupInfo)

	var itemIDs []string
	var itemCandidateKeys [][]string // memberKey ("zone#suffix"), current primary first.

	// Walk |assignments| (sorted by ItemID, then zone, then suffix),
	// grouping consecutive rows sharing an ItemID into a single Item.
	for i := 0; i != len(assignments); {
		var a0 = assignmentAt(assignments, i)
		var limit = i
		for limit != len(assignments) && assignmentAt(assignments, limit).ItemID == a0.ItemID {
			limit++
		}
		var group = itemGroup(a0.ItemID)
		if rawGroupCounts[group] < 2 {
			i = limit
			continue // Not a tracked multi-Item group.
		}
		var gi = groups[group]
		if gi == nil {
			gi = &groupInfo{members: make(map[string]bool), reachable: make(map[string]int)}
			groups[group] = gi
		}
		gi.itemCount++

		var primaryKey string
		var keys []string
		for j := i; j != limit; j++ {
			var a = assignmentAt(assignments, j)
			var key = memberKeyOf(a)
			gi.members[key] = true
			gi.reachable[key]++
			if a.Slot == 0 {
				primaryKey = key
			} else {
				keys = append(keys, key)
			}
		}
		if primaryKey != "" {
			keys = append([]string{primaryKey}, keys...)
		}
		if len(keys) != 0 {
			itemIDs = append(itemIDs, a0.ItemID)
			itemCandidateKeys = append(itemCandidateKeys, keys)
		}
		i = limit
	}

	var firstItemNodeID = pr.SinkID + 1
	var firstGroupMemberNodeID = firstItemNodeID + pr.NodeID(len(itemIDs))

	var groupNames []string
	for g := range groups {
		groupNames = append(groupNames, g)
	}
	sort.Strings(groupNames) // Deterministic NodeID assignment.

	var groupMemberOf = make(map[string]pr.NodeID)
	var groupMemberCap []pr.Rate
	var groupMemberKey []string
	var nextID = firstGroupMemberNodeID

	for _, g := range groupNames {
		var gi = groups[g]
		var memberKeys []string
		for k := range gi.members {
			memberKeys = append(memberKeys, k)
		}
		sort.Strings(memberKeys) // Deterministic NodeID assignment & cap tie-break.
		var caps = groupMemberCaps(gi.itemCount, gi.reachable, memberKeys)

		for _, k := range memberKeys {
			groupMemberOf[g+"\x00"+k] = nextID
			groupMemberCap = append(groupMemberCap, pr.Rate(caps[k]))
			groupMemberKey = append(groupMemberKey, k)
			nextID++
		}
	}

	var itemsOut = make([]primaryFlowItem, len(itemIDs))
	for i, itemID := range itemIDs {
		var group = itemGroup(itemID)
		var candidates = make([]pr.NodeID, len(itemCandidateKeys[i]))
		for j, key := range itemCandidateKeys[i] {
			candidates[j] = groupMemberOf[group+"\x00"+key]
		}
		itemsOut[i] = primaryFlowItem{itemID: itemID, candidates: candidates}
	}

	return &primaryFlowNetwork{
		items:                  itemsOut,
		groupMemberCap:         groupMemberCap,
		groupMemberKey:         groupMemberKey,
		firstItemNodeID:        firstItemNodeID,
		firstGroupMemberNodeID: firstGroupMemberNodeID,
	}
}

// groupMemberCaps computes each Member's precise fair-share cap of a
// group's |itemCount| primaries, given |reachable| (how many of the
// group's Items each Member actually replicates, and so could ever be
// primary for -- see groupInfo.reachable) and the group's |memberKeys|
// (sorted, for a deterministic tie-break).
//
// Unlike buildGroupMemberArc's use of scaleAndRound (a uniform ceiling
// applied to *every* Member), this must give each Member its own precise
// share of the remainder, such that caps sum to exactly |itemCount| -- not
// more. A uniform ceiling leaves slack (eg ceil(16/3)=6 given to all 3
// Members sums to 18, well over the 16 actually available), and that
// slack is enough for an already-skewed distribution (eg 4/6/6) to
// satisfy every Member's cap without any Member ever being forced over
// it. Since Arcs() always tries an Item's current primary first (for
// stability -- see discharge()'s Arc-order shift discussion there), a
// merely loose cap provides no pressure to correct that skew: the solver
// simply finds this already-acceptable arrangement as *a* maximum flow
// and stops, never discovering the more balanced one.
//
// It's not enough to just divide |itemCount| evenly, either: a Member may
// structurally be unable to reach an even share, no matter how primaries
// are chosen, because it simply doesn't replicate enough of the group's
// Items to begin with (eg a recently-scaled Member still catching up on
// replica membership). Naively capping every Member at an even share
// would then leave that Member's shortfall for push/relabel's dynamic,
// pressure-triggered relaxation (to unbounded capacity) to resolve --
// which has no deterministic tie-break for *which* of several eligible
// Members should absorb the overflow, and so can flap between equally
// valid choices round over round exactly like the arc-shift oscillation
// above, just one layer higher (across Members instead of within a single
// Item's own candidates).
//
// So instead, this "water-fills" the exact remainder across Members
// biased by their reachability: any Member whose reachability falls short
// of an even split of the *remaining* demand is capped at its reachable
// count (it structurally can't be pushed any higher), and its shortfall
// is folded back into the pool redistributed evenly (floor share, +1 for
// only as many Members as the new remainder requires) among the Members
// still able to accept more. This repeats until every remaining Member's
// share is within its means, at which point the result is a pure
// function of input state -- no relaxation, and no round-over-round
// ambiguity, is needed to reach it.
func groupMemberCaps(itemCount int, reachable map[string]int, memberKeys []string) map[string]int {
	var caps = make(map[string]int, len(memberKeys))
	var remaining = append([]string(nil), memberKeys...) // Already sorted by caller.
	var demand = itemCount

	for len(remaining) != 0 {
		var floorShare, remainder = demand / len(remaining), demand % len(remaining)
		var unconstrained []string // Members able to meet this round's even share.

		for i, k := range remaining {
			var share = floorShare
			if i < remainder {
				share++
			}
			if reachable[k] < share {
				caps[k] = reachable[k] // Structurally capped: shed to the remaining pool.
				demand -= reachable[k]
			} else {
				unconstrained = append(unconstrained, k)
			}
		}
		if len(unconstrained) == len(remaining) {
			// No Member was reachability-constrained this round: finalize
			// the even split just computed and we're done.
			for i, k := range remaining {
				var share = floorShare
				if i < remainder {
					share++
				}
				caps[k] = share
			}
			break
		}
		remaining = unconstrained
	}
	return caps
}

func (fn *primaryFlowNetwork) Nodes() int {
	return int(fn.firstGroupMemberNodeID) + len(fn.groupMemberCap)
}

func (fn *primaryFlowNetwork) InitialHeight(id pr.NodeID) pr.Height {
	var h pr.Height
	if id < fn.firstGroupMemberNodeID {
		h = 2 // Item node.
	} else {
		h = 1 // Group-Member node.
	}
	if max := pr.Height(fn.Nodes() - 1); h > max {
		h = max
	}
	return h
}

func (fn *primaryFlowNetwork) Arcs(mf *pr.MaxFlow, id pr.NodeID, page pr.PageToken) ([]pr.Arc, pr.PageToken) {
	if id == pr.SourceID {
		var arcs = make([]pr.Arc, len(fn.items))
		for i := range fn.items {
			arcs[i] = pr.Arc{To: fn.firstItemNodeID + pr.NodeID(i), Capacity: 1}
		}
		return arcs, pr.PageEOF

	} else if id == pr.SinkID {
		panic("unexpected Arcs call with id == pr.SinkID")

	} else if id < fn.firstGroupMemberNodeID {
		var item = fn.items[id-fn.firstItemNodeID]
		var n = len(item.candidates)
		var arcs = fn.scratch[:n]

		// discharge() deterministically shifts the Arc index it examines
		// first by `id % len(arcs)` (see push_relabel.go), to avoid many
		// Nodes of common structure all preferring the same first Arc.
		// Left uncountered, that shift would just as often present the
		// Item's *non*-primary candidate first as its primary one, silently
		// defeating our intended preference below and causing primaries to
		// perpetually oscillate between equally fair-share candidates
		// (each round "correcting" a departure the shift itself caused).
		// We counteract it by rotating candidates so the current primary
		// (candidates[0], if any) always lands on the very Arc index the
		// shift will visit first, regardless of its value.
		var shift = int(id) % n
		for i, c := range item.candidates {
			// PushFront biases the solver to retain the current primary's
			// Flow once established, rather than shuffle it elsewhere
			// absent a fair-share reason to move it.
			arcs[(i+shift)%n] = pr.Arc{To: c, Capacity: 1, PushFront: i == 0}
		}
		return arcs, pr.PageEOF

	} else {
		var gm = int(id - fn.firstGroupMemberNodeID)
		var c = unboundedGroupCapacity
		if mf.RelativeHeight(id) < primaryGroupMemberOverflowThreshold {
			c = fn.groupMemberCap[gm]
		}
		fn.scratch[0] = pr.Arc{To: pr.SinkID, Capacity: c}
		return fn.scratch[:1], pr.PageEOF
	}
}

// extractPrimaries returns, for each Item modeled by this network, the
// Member key ("zone#suffix") which the max-flow solution selected as its
// primary. An Item is omitted if (unexpectedly) it received no flow at all.
func (fn *primaryFlowNetwork) extractPrimaries(mf *pr.MaxFlow) map[string]string {
	var out = make(map[string]string, len(fn.items))
	for i := range fn.items {
		var nodeID = fn.firstItemNodeID + pr.NodeID(i)
		mf.Flows(nodeID, func(flow pr.Flow) {
			var gm = int(flow.To - fn.firstGroupMemberNodeID)
			out[fn.items[i].itemID] = fn.groupMemberKey[gm]
		})
	}
	return out
}
