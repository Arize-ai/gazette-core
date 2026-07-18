package allocator

import (
	"sort"
	"strings"

	pr "go.gazette.dev/core/allocator/sparse_push_relabel"
	"go.gazette.dev/core/keyspace"
)

// sparseFlowNetwork models an allocator.State as a flow network, representing
// Items, "Zone Items" (which is an Item within the context of a single zone),
// Group-Members (which is a "group" of Items -- see itemGroup -- within the
// context of a single Member), and Members. Pictorially, the network
// resembles:
//
//	              Items        Zone-Items       Group-Members     Members
//	              -----        ----------       -------------     -------
//
//	                           +-------+
//	                           |       |---\    +---------+
//	                          >|item1/A|    --->|         |
//	                        -/ |       |\       |A/groupX |\
//	                       /   +-------+ -\    ^|         | -\    +---------+
//	             +-----+ -/    +-------+   -\ / +---------+   \  ^|         |
//	             |     |/      |       |     /\                \ |A/memberX|
//	            >|item1|------>|item1/B|    /  \ +---------+     >|         |
//	+------+  -/ |     |       |       |\  /    >|         |   -/ +---------+
//	|      |-/   +-----+       +-------+ \/     |A/groupY |--/          .
//	|source|                             /\    >|         |             .
//	|      |-\   +-----+       +-------+/  \/   +---------+             .
//	+------+  -\ |     |       |       |  -/\                     +--------+
//	            >|item2|------>|item2/A|-/   \                   >|        |
//	             |     |\      |       |      \ +---------+     /-| target |
//	             +-----+ -\    +-------+       v|         |    /  |        |
//	                       \   +-------+        |B/groupZ |---/   +--------+
//	                        -\ |       |    --->|         |
//	                          >|item2/B|---/    +---------+
//	                           |       |
//	                           +-------+
//
// The network also represents a number of constraints and goals:
//
//   - Desired Item replication is captured by the capacity from source to Item.
//   - Zone replication constraints (distribution of each Item across 2+ zones) are
//     captured in arcs from Items to Zone Items. Goals for maintaining current
//     assignments and balancing evenly across zones are also expressed.
//   - A preference for current assignments is reflected in arcs from Zone Items
//     onward (either directly to Members, or via an intervening Group-Member --
//     see below).
//   - Items sharing a common logical "group" (such as partitions of a common
//     topic; see itemGroup) are prevented from unfairly clustering onto a
//     subset of Members. Each (zone, group, Member) triple is modeled as a
//     Group-Member node, through which every Zone-Item of that group and zone
//     must flow en-route to the Member. The single arc from a Group-Member to
//     its Member is capacity-bound to that Member's fair share of the group,
//     which -- exactly like Member fair-share below -- is relaxed under
//     sufficient network "pressure" so that group fairness never prevents an
//     otherwise-achievable maximum assignment.
//   - Desired "fair share" scaled capacity and upper-bound capacity is reflected
//     by arcs from Members to the Sink.
//
// The basic strategy used is to greedily coerce the push/relabel solver towards
// a solution which achieves optimization goals (minimal updates & even balancing)
// while still staying within the algorithmic scaffolding of push/relabel,
// ensuring that a correct maximum-flow solution is ultimately arrived at.
//
// This coercing is expressed through the order in which Arcs are presented to the
// solver, and also by strategically constraining the capacities of those Arcs.
// As the solver finds it is unable to follow the "garden path" (not all network
// excess can be allocated), and as back-tracking builds "pressure" in the network
// (expressed via node heights), the relevant Arc capacities at each step are
// relaxed until a maximal assignment is achieved.
type sparseFlowNetwork struct {
	*State
	myItems     keyspace.KeyValues // Slice of State.Items included in this network.
	myItemSlots int                // Summed of replication slots attributable just to myItems.

	firstItemNodeID        pr.NodeID // First Item NodeID in the graph.
	firstZoneItemNodeID    pr.NodeID // First Zone-Item NodeID in the graph.
	firstGroupMemberNodeID pr.NodeID // First Group-Member NodeID in the graph.
	firstMemberNodeID      pr.NodeID // First Member NodeID in the graph.

	// For each zone-item, the offset into State.Assignments of its first assignment.
	zoneItemAssignments []keyspace.KeyValues
	// For each zone, an index of member ID suffix to its NodeID.
	memberSuffixIdxByZone []map[string]pr.NodeID
	// For each zone, a slice of Arcs to all members of that zone.
	allZoneItemArcsByZone [][]pr.Arc

	// groupIndex maps a "multi-item" group name (having two or more Items
	// within myItems -- see itemGroup) to a dense index over [0, numGroups).
	// A group having only a single Item is not tracked here: with just one
	// Item, there's nothing to unfairly cluster within a single zone, so its
	// Zone-Item connects directly to Members exactly as if grouping did not
	// exist at all.
	groupIndex map[string]int
	// groupItemCounts[gi] is the demand -- in Zone-Item slots -- that the
	// group having dense index gi places on a single zone, used to compute
	// each Member's fair share of the group's Items within that zone. It's
	// the group's raw Item count in the common multi-zone case (each Item
	// ordinarily places one replica per zone), but its total replication
	// slots (Item count * DesiredReplication) when there's only a single
	// zone, since then every replica of every Item must land within it.
	groupItemCounts []int
	// zoneMemberCount[zone] is the count of Members within that zone.
	zoneMemberCount []int
	// groupMemberBaseByZone[zone] is the first Group-Member NodeID allotted
	// to that zone. Nodes for group `gi` and the Member at zone-relative
	// position `pos` (of zoneMemberCount[zone]) occupy NodeID:
	//   groupMemberBaseByZone[zone] + gi*zoneMemberCount[zone] + pos
	groupMemberBaseByZone []pr.NodeID
	// memberPosByZone[zone] indexes a Member suffix to its zone-relative
	// position, used to locate the Group-Member node of a current Assignment.
	memberPosByZone []map[string]int
	// groupMemberTarget[gm], indexed by (NodeID - firstGroupMemberNodeID),
	// gives the actual Member NodeID ultimately reached by that Group-Member
	// node. This lets extractAssignments resolve a Flow terminating at a
	// Group-Member back to the underlying Member.
	groupMemberTarget []pr.NodeID
	// allGroupMemberArcsByZoneGroup[zone][gi] enumerates an Arc to the
	// Group-Member node of each Member of `zone`, for the group having dense
	// index gi. It's structurally identical to allZoneItemArcsByZone[zone],
	// but arcs terminate at that group's Group-Member nodes instead of
	// directly at Members.
	allGroupMemberArcsByZoneGroup [][][]pr.Arc

	// scratch is a small slice of Arcs for (re)use without allocating. We'll
	// want up-to the number of zones, or the number of Assignments of an Item
	// within a zone -- both should be small, but if we overflow that's fine,
	// as append() will just allocate from heap instead.
	scratch [8]pr.Arc
}

const (
	// By network construction, the push/relabel algorithm will relabel an Item
	// node to a RelativeHeight() of 1 (relative to the source node) just prior
	// to pushing back to the source, which terminates the algorithm.
	//
	// Where we ordinarily require an Item to be replicated across two zones, if
	// we reach this height, we'll instead allow a single zone to hold all Item
	// replicas (as the alternative is not fully replicating the Item at all).
	itemOverflowThreshold = 1
	// Also by network construction, if a Group-Member node is allowed to
	// reach a RelativeHeight() of `itemOverflowThreshold`, then we may cause
	// `itemOverflowThreshold` to be breached, by the very same reasoning
	// documented on memberOverflowThreshold below -- except that a
	// Group-Member sits exactly where a Member used to sit prior to the
	// introduction of this node layer (two hops from Item: Group-Member ->
	// Zone-Item -> Item), so it inherits the very same threshold value that
	// memberOverflowThreshold used to have, before this layer was introduced.
	groupMemberOverflowThreshold = -1
	// Also by network construction, if a Member node is allowed to reach a
	// RelativeHeight of `groupMemberOverflowThreshold`, then we may cause
	// `groupMemberOverflowThreshold` to be breached. Eg:
	// - Member height S+1 pushes along residual to Group-Member height S.
	// - Group-Member height S pushes along residual to Zone-Item height S-1.
	// - Zone-Item height S-1 pushes to Item having height S-2.
	// - Item is relabeled to S+1.
	//
	// Ideally we evenly balance Items across Members, but we'd rather a Member
	// take on more than its fair share of Items than cause an Item to not be
	// replicated across at least two zones. In network terms, we'd rather a
	// Member overflow before we allow an Item to overflow, and we thus never
	// want a Member to reach RelativeHeight of `groupMemberOverflowThreshold`
	// if capacity remains.
	//
	// Member is now one hop further from Item than it was before Group-Member
	// nodes were introduced (Member -> Group-Member -> Zone-Item -> Item,
	// vs. the prior Member -> Zone-Item -> Item), so its threshold is shifted
	// one lower than groupMemberOverflowThreshold, following the very same
	// "-1 per hop away from Item" pattern used to derive that threshold from
	// itemOverflowThreshold in the first place.
	//
	// *However*, note that a relabeling may take us from height S-1 => S+1,
	// skipping S, so we must bound conservatively to ensure this never happens.
	//
	// Note that our push/relabel solver implements the label gap heuristic,
	// which instantly re-sets a subset of nodes to a new height. Usually
	// that height is len(nodes) + 1, but we use len(nodes) - 1 to give the
	// solver time to fully explore these overflow heuristics.
	memberOverflowThreshold = -2

	// unboundedGroupCapacity is used in place of a group's fair-share cap
	// once the network has built sufficient pressure (see
	// groupMemberOverflowThreshold) to indicate the cap cannot otherwise be
	// satisfied. It's large enough to never itself be a binding constraint;
	// the Member's own arcs to the Sink remain the ultimate limiter.
	unboundedGroupCapacity pr.Rate = 1 << 24

	pageItemArcsUniform    = pr.PageInitial + 1
	pageItemArcsRMinusOne  = pageItemArcsUniform + 1
	pageZoneItemAllMembers = pageItemArcsRMinusOne + 1
)

// newSparseFlowNetwork builds a *sparseFlowNetwork around the given State
// and partitioned sub-slice of State.Items.
func newSparseFlowNetwork(s *State, myItems keyspace.KeyValues) *sparseFlowNetwork {

	// Nodes are ordered as:
	//  - Source node, then
	//  - Sink node, then
	//  - Item Nodes, then
	//  - Zone-Item Nodes, then
	//  - Group-Member Nodes, then
	//  - Member Nodes.
	var firstItemNodeID = pr.SinkID + 1 // == 2.
	var firstZoneItemNodeID = firstItemNodeID + pr.NodeID(len(myItems))
	var firstGroupMemberNodeID = firstZoneItemNodeID + pr.NodeID(len(myItems)*len(s.Zones))

	// Left-join |Items| with |Assignments| (which is ordered on Item ID,
	// Member zone, Member suffix) to build an index of zone-item to the
	// offset of its first Assignment (or, the offset to where its Assignment
	// would place if it had one).
	var zoneItemAssignments = make([]keyspace.KeyValues, len(myItems)*len(s.Zones))

	// Accelerate our left-join by skipping to the first assignment of `myItems` via binary search.
	var pivot, _ = s.Assignments.Search(ItemAssignmentsPrefix(s.KS, itemAt(myItems, 0).ID))
	var myAssignments = s.Assignments[pivot:]
	var myItemSlots int

	// Determine each Item's logical group (see itemGroup), and count how
	// many Items of myItems -- and how many total replication slots -- fall
	// into each. Groups with fewer than two Items are dropped: with a single
	// Item, there's nothing to unfairly cluster within a zone.
	var rawGroupCounts = make(map[string]int)
	var rawGroupSlots = make(map[string]int)
	for item := range myItems {
		var group = itemGroup(itemAt(myItems, item).ID)
		rawGroupCounts[group]++
		rawGroupSlots[group] += itemAt(myItems, item).DesiredReplication()
	}
	var groupNames []string
	for group, n := range rawGroupCounts {
		if n >= 2 {
			groupNames = append(groupNames, group)
		}
	}
	sort.Strings(groupNames) // Deterministic dense index assignment.

	var groupIndex = make(map[string]int, len(groupNames))
	var groupItemCounts = make([]int, len(groupNames))
	for gi, group := range groupNames {
		groupIndex[group] = gi
		if len(s.Zones) == 1 {
			groupItemCounts[gi] = rawGroupSlots[group]
		} else {
			groupItemCounts[gi] = rawGroupCounts[group]
		}
	}
	var numGroups = len(groupNames)

	var it = LeftJoin{
		LenL: len(myItems),
		LenR: len(myAssignments),
		Compare: func(l, r int) int {
			return strings.Compare(itemAt(myItems, l).ID, assignmentAt(myAssignments, r).ItemID)
		},
	}
	for cur, ok := it.Next(); ok; cur, ok = it.Next() {
		var item = cur.Left
		var assignments = myAssignments[cur.RightBegin:cur.RightEnd]
		myItemSlots += myItems[item].Decoded.(Item).DesiredReplication()

		// Left-join zones with |assignments| of this |item|.
		var it2 = LeftJoin{
			LenL: len(s.Zones),
			LenR: len(assignments),
			Compare: func(l, r int) int {
				return strings.Compare(s.Zones[l], assignmentAt(assignments, r).MemberZone)
			},
		}
		for cur2, ok2 := it2.Next(); ok2; cur2, ok2 = it2.Next() {
			var zoneItem = item*len(s.Zones) + cur2.Left
			zoneItemAssignments[zoneItem] = assignments[cur2.RightBegin:cur2.RightEnd]
		}
	}

	// Pass 1: left-join |Zones| with |Members| purely to determine each
	// zone's Member count and starting offset into s.Members. This lets us
	// compute the Group-Member node layout (which depends on every zone's
	// Member count) before laying out any Arcs.
	var zoneMemberCount = make([]int, len(s.Zones))
	var zoneMembersBegin = make([]int, len(s.Zones))

	it = LeftJoin{
		LenL: len(s.Zones),
		LenR: len(s.Members),
		Compare: func(l, r int) int {
			return strings.Compare(s.Zones[l], memberAt(s.Members, r).Zone)
		},
	}
	for cur, ok := it.Next(); ok; cur, ok = it.Next() {
		zoneMemberCount[cur.Left] = cur.RightEnd - cur.RightBegin
		zoneMembersBegin[cur.Left] = cur.RightBegin
	}

	// Lay out Group-Member nodes: for each zone, `numGroups * zoneMemberCount[zone]` nodes.
	var groupMemberBaseByZone = make([]pr.NodeID, len(s.Zones))
	var nextID = firstGroupMemberNodeID
	for zone := range s.Zones {
		groupMemberBaseByZone[zone] = nextID
		nextID += pr.NodeID(numGroups * zoneMemberCount[zone])
	}
	var firstMemberNodeID = nextID

	// Pass 2: build Member-facing indices and Arcs, now that firstMemberNodeID
	// and groupMemberBaseByZone are both known.
	var memberSuffixIdxByZone = make([]map[string]pr.NodeID, len(s.Zones))
	var memberPosByZone = make([]map[string]int, len(s.Zones))
	var allZoneItemArcsByZone = make([][]pr.Arc, len(s.Zones))
	var allGroupMemberArcsByZoneGroup = make([][][]pr.Arc, len(s.Zones))
	var groupMemberTarget []pr.NodeID // Built incrementally below, in NodeID order.

	for zone := range s.Zones {
		var nMembers = zoneMemberCount[zone]
		var membersBegin = zoneMembersBegin[zone]

		memberSuffixIdxByZone[zone] = make(map[string]pr.NodeID, nMembers)
		memberPosByZone[zone] = make(map[string]int, nMembers)
		allZoneItemArcsByZone[zone] = make([]pr.Arc, nMembers)

		for pos := 0; pos != nMembers; pos++ {
			var member = memberAt(s.Members, membersBegin+pos)
			var id = firstMemberNodeID + pr.NodeID(membersBegin+pos)

			memberSuffixIdxByZone[zone][member.Suffix] = id
			memberPosByZone[zone][member.Suffix] = pos
			allZoneItemArcsByZone[zone][pos] = pr.Arc{To: id, Capacity: 1}
		}

		allGroupMemberArcsByZoneGroup[zone] = make([][]pr.Arc, numGroups)
		for gi := 0; gi != numGroups; gi++ {
			var arcs = make([]pr.Arc, nMembers)
			for pos := 0; pos != nMembers; pos++ {
				var gmID = groupMemberBaseByZone[zone] + pr.NodeID(gi*nMembers+pos)
				arcs[pos] = pr.Arc{To: gmID, Capacity: 1}

				// groupMemberTarget is indexed by (gmID - firstGroupMemberNodeID),
				// which increases monotonically as we walk zones and groups in
				// this same nested order, so a simple append suffices.
				var memberID = firstMemberNodeID + pr.NodeID(membersBegin+pos)
				groupMemberTarget = append(groupMemberTarget, memberID)
			}
			allGroupMemberArcsByZoneGroup[zone][gi] = arcs
		}
	}

	var fs = &sparseFlowNetwork{
		State:                         s,
		myItems:                       myItems,
		myItemSlots:                   myItemSlots,
		firstItemNodeID:               firstItemNodeID,
		firstZoneItemNodeID:           firstZoneItemNodeID,
		firstGroupMemberNodeID:        firstGroupMemberNodeID,
		firstMemberNodeID:             firstMemberNodeID,
		zoneItemAssignments:           zoneItemAssignments,
		memberSuffixIdxByZone:         memberSuffixIdxByZone,
		allZoneItemArcsByZone:         allZoneItemArcsByZone,
		groupIndex:                    groupIndex,
		groupItemCounts:               groupItemCounts,
		zoneMemberCount:               zoneMemberCount,
		groupMemberBaseByZone:         groupMemberBaseByZone,
		memberPosByZone:               memberPosByZone,
		groupMemberTarget:             groupMemberTarget,
		allGroupMemberArcsByZoneGroup: allGroupMemberArcsByZoneGroup,
	}
	return fs
}

func (fs *sparseFlowNetwork) Nodes() int {
	return int(fs.firstMemberNodeID) + len(fs.Members)
}

func (fs *sparseFlowNetwork) InitialHeight(id pr.NodeID) pr.Height {
	var h pr.Height
	if id < fs.firstZoneItemNodeID {
		h = 4 // Item node.
	} else if id < fs.firstGroupMemberNodeID {
		h = 3 // Zone-Item node.
	} else if id < fs.firstMemberNodeID {
		h = 2 // Group-Member node.
	} else {
		h = 1 // Member node.
	}
	// heightCounts is sized to Nodes(), so every returned height must stay
	// within [0, Nodes()-1]. The four-tier scheme above assumes enough nodes
	// exist to justify height 4, which can be untrue for tiny networks (e.g.
	// items with zero current members). Clamping is safe: InitialHeight is
	// only a distance-to-sink heuristic, not a correctness requirement.
	if max := pr.Height(fs.Nodes() - 1); h > max {
		h = max
	}
	return h
}

func (fs *sparseFlowNetwork) Arcs(mf *pr.MaxFlow, id pr.NodeID, page pr.PageToken) ([]pr.Arc, pr.PageToken) {
	if id == pr.SourceID {
		return fs.buildSourceArcs(), pr.PageEOF // Arcs from the Source to each Item.

	} else if id == pr.SinkID {
		// push/relabel never discharges from the sink, so we never expect to
		// see a corresponding Arcs() call.
		panic("unexpected Arcs call with id == pr.SinkID")

	} else if id < fs.firstZoneItemNodeID {
		var item = int(id - fs.firstItemNodeID)
		var r = itemAt(fs.myItems, item).DesiredReplication()

		// Enumerate Arcs from the Item to each of its Zone-Item Nodes.
		// If there is only one zone, or we will next push back to the Source,
		// then do not constrain the capacity of each Zone-Item Arc
		// (all of the Item's flow may go to any Zone-Item).
		if len(fs.Zones) == 1 || mf.RelativeHeight(id) == itemOverflowThreshold {
			return fs.buildAllItemArcs(item, r), pr.PageEOF
		}

		// Otherwise, enumerate arcs which prefer:
		// - To maintain current Item / zone Assignments, then
		// - Uniformly balancing the Item across zones, then
		// - Any zone, so long as at least two zones are utilized.
		switch page {
		case pr.PageInitial:
			return fs.buildCurrentItemArcs(item, max(r-1, 1)), pageItemArcsUniform
		case pageItemArcsUniform:
			var uniform = scaleAndRound(r, 1, len(fs.Zones))
			return fs.buildAllItemArcs(item, uniform), pageItemArcsRMinusOne
		case pageItemArcsRMinusOne:
			return fs.buildAllItemArcs(item, max(r-1, 1)), pr.PageEOF
		default:
			panic("invalid PageToken")
		}

	} else if id < fs.firstGroupMemberNodeID {
		var zoneItem = int(id - fs.firstZoneItemNodeID)

		// Cycle through two pages of arcs:
		// - Arcs which reflect current Assignments of the Zone-Item, onward
		//   to zone Members (possibly via an intervening Group-Member).
		// - Arcs which represent the total set of zone Members (likewise,
		//   possibly via Group-Member nodes).
		// Intuitively: we prefer to keep current Member Assignments, but will allow
		// a new assignment to any of the zone's Members.
		switch page {
		case pr.PageInitial:
			return fs.buildCurrentZoneItemArcs(zoneItem), pageZoneItemAllMembers
		case pageZoneItemAllMembers:
			return fs.buildAllZoneMemberArcs(zoneItem), pr.PageEOF
		default:
			panic("invalid PageToken")
		}

	} else if id < fs.firstMemberNodeID {
		return fs.buildGroupMemberArc(mf, id), pr.PageEOF

	} else {
		var member = int(id - fs.firstMemberNodeID)
		return fs.buildMemberArc(mf, id, member), pr.PageEOF
	}
}

// buildSourceArcs enumerates an Arc for each Item node, nominally having capacity
// of the Item's desired replication. If the total number of Item slots greatly
// exceeds Member slots, this degrades the performance and stability of the push/
// relabel solver; we therefore globally bound Item capacities to the number of
// available Member slots.
func (fs *sparseFlowNetwork) buildSourceArcs() []pr.Arc {
	var arcs = make([]pr.Arc, len(fs.myItems))
	var remaining = fs.MemberSlots

	for item := range fs.myItems {
		var c = itemAt(fs.myItems, item).DesiredReplication()

		if c > remaining {
			c = remaining
		}
		remaining -= c

		arcs[item] = pr.Arc{
			To:       fs.firstItemNodeID + pr.NodeID(item),
			Capacity: pr.Rate(c),
		}
	}
	return arcs
}

// buildAllItemArcs enumerates an Arc for each ZoneItem node of the Item,
// each having capacity C.
func (fs *sparseFlowNetwork) buildAllItemArcs(item int, C int) []pr.Arc {
	var (
		arcs = fs.scratch[:0]
		lz   = len(fs.Zones)
	)

	for zone := 0; zone != lz; zone++ {
		arcs = append(arcs, pr.Arc{
			To:       fs.firstZoneItemNodeID + pr.NodeID(item*lz+zone),
			Capacity: pr.Rate(C),
		})
	}
	return arcs
}

// buildCurrentItemArcs enumerates an Arc for each ZoneItem of the Item
// having current Assignments. Arc capacities are the smaller of |bound|
// and the number of current Assignments.
func (fs *sparseFlowNetwork) buildCurrentItemArcs(item int, bound int) []pr.Arc {
	var (
		arcs = fs.scratch[:0]
		lz   = len(fs.Zones)
	)
	for zone := 0; zone != lz; zone++ {
		var n = len(fs.zoneItemAssignments[item*lz+zone])
		if n > bound {
			n = bound
		}
		if n != 0 {
			arcs = append(arcs, pr.Arc{
				To:        fs.firstZoneItemNodeID + pr.NodeID(item*lz+zone),
				Capacity:  pr.Rate(n),
				PushFront: true,
			})
		}
	}
	return arcs
}

// buildMemberArc from member `member` to the sink.
func (fs *sparseFlowNetwork) buildMemberArc(mf *pr.MaxFlow, id pr.NodeID, member int) []pr.Arc {
	var c = fs.memberEffectiveLimit(member)

	// Scale ItemLimit by the relative share of ItemSlots within
	// our subset of the global assignment problem.
	c = scaleAndRound(c, fs.myItemSlots, fs.ItemSlots)

	if mf.RelativeHeight(id) < memberOverflowThreshold {
		// Further scale to our relative "fair share" items.
		// Intuitively, the Member node will resist having more than its fair share of
		// assignments until sufficient pressure builds within the network to indicate
		// that not all assignments can otherwise be made, at which point we'll
		// allow assignments up to our (scaled) full capacity.
		c = scaleAndRound(c, fs.ItemSlots, fs.MemberSlots)
	}
	fs.scratch[0] = pr.Arc{
		To:       pr.SinkID,
		Capacity: pr.Rate(c),
	}
	return fs.scratch[:1]
}

// buildGroupMemberArc returns the single Arc from a Group-Member node to its
// underlying Member. Its capacity is ordinarily the Member's fair share of
// the group's Items within this zone, but is relaxed to unboundedGroupCapacity
// once sufficient network pressure indicates that fair share is otherwise
// unattainable (see groupMemberOverflowThreshold).
func (fs *sparseFlowNetwork) buildGroupMemberArc(mf *pr.MaxFlow, id pr.NodeID) []pr.Arc {
	var offset = int(id - fs.firstGroupMemberNodeID)

	// Recover (zone, group index, member position) from the dense offset.
	// Zones are laid out in order, each occupying numGroups*zoneMemberCount[zone] nodes.
	var zone int
	for zone = 0; zone != len(fs.Zones); zone++ {
		var span = len(fs.groupItemCounts) * fs.zoneMemberCount[zone]
		if offset < span {
			break
		}
		offset -= span
	}
	var gi = offset / fs.zoneMemberCount[zone]

	var c = unboundedGroupCapacity
	if mf.RelativeHeight(id) < groupMemberOverflowThreshold {
		c = pr.Rate(scaleAndRound(fs.groupItemCounts[gi], 1, fs.zoneMemberCount[zone]))
	}

	fs.scratch[0] = pr.Arc{
		To:       fs.groupMemberTarget[id-fs.firstGroupMemberNodeID],
		Capacity: c,
	}
	return fs.scratch[:1]
}

// buildCurrentZoneItemArcs from zone-item |zoneItem| onward to each Member
// node of the zone having a current assignment -- via an intervening
// Group-Member node, if the Item belongs to a multi-Item group.
func (fs *sparseFlowNetwork) buildCurrentZoneItemArcs(zoneItem int) []pr.Arc {
	var (
		arcs        = fs.scratch[:0]
		zone        = zoneItem % len(fs.Zones)
		gi, grouped = fs.groupIndexOfZoneItem(zoneItem)
	)
	for _, a := range fs.zoneItemAssignments[zoneItem] {
		var suffix = a.Decoded.(Assignment).MemberSuffix

		var to pr.NodeID
		if grouped {
			pos, ok := fs.memberPosByZone[zone][suffix]
			if !ok {
				continue
			}
			to = fs.groupMemberBaseByZone[zone] + pr.NodeID(gi*fs.zoneMemberCount[zone]+pos)
		} else {
			id, ok := fs.memberSuffixIdxByZone[zone][suffix]
			if !ok {
				continue
			}
			to = id
		}
		arcs = append(arcs, pr.Arc{
			To:        to,
			Capacity:  1,
			PushFront: true,
		})
	}
	return arcs
}

// buildAllZoneMemberArcs returns the "all members" page of Arcs for
// zone-item |zoneItem|: either directly to every Member of the zone (for a
// singleton-group Item), or to every Group-Member node of the zone for the
// Item's group.
func (fs *sparseFlowNetwork) buildAllZoneMemberArcs(zoneItem int) []pr.Arc {
	var zone = zoneItem % len(fs.Zones)
	if gi, grouped := fs.groupIndexOfZoneItem(zoneItem); grouped {
		return fs.allGroupMemberArcsByZoneGroup[zone][gi]
	}
	return fs.allZoneItemArcsByZone[zone]
}

// groupIndexOfZoneItem returns the dense group index of the Item underlying
// |zoneItem|, and whether that group is tracked at all (ie, has 2+ Items).
func (fs *sparseFlowNetwork) groupIndexOfZoneItem(zoneItem int) (int, bool) {
	var item = zoneItem / len(fs.Zones)
	var gi, ok = fs.groupIndex[itemGroup(itemAt(fs.myItems, item).ID)]
	return gi, ok
}

// itemGroup returns the logical group of an Item ID, used to balance Items
// which share a common grouping (such as being partitions of a common topic)
// evenly across Members. If the Item ID's final '/'-delimited path segment
// ends in one or more decimal digits, the group is the ID with that trailing
// segment (and its preceding '/') removed -- eg "a-topic/part-003" groups
// with other Items as "a-topic". Otherwise (including when the ID has no
// '/' at all), the entire ID is its own singleton group.
func itemGroup(id string) string {
	var slash = strings.LastIndexByte(id, '/')
	if slash < 0 {
		return id
	}
	var tail = id[slash+1:]

	var i = len(tail)
	for i > 0 && tail[i-1] >= '0' && tail[i-1] <= '9' {
		i--
	}
	if i == len(tail) {
		return id // Final segment has no trailing digits.
	}
	return id[:slash]
}

// extractAssignments appends and returns the set of ordered []Assignment
// implied by the MaxFlow solution.
func (fs *sparseFlowNetwork) extractAssignments(g *pr.MaxFlow, out []Assignment) []Assignment {
	var lz = len(fs.Zones)

	for item := range fs.myItems {
		var itemID = itemAt(fs.myItems, item).ID
		var sortFrom = len(out)

		for zone := 0; zone != lz; zone++ {
			var nodeID = fs.firstZoneItemNodeID + pr.NodeID(item*lz+zone)

			g.Flows(nodeID, func(flow pr.Flow) {
				var memberNodeID = flow.To
				if memberNodeID >= fs.firstGroupMemberNodeID && memberNodeID < fs.firstMemberNodeID {
					memberNodeID = fs.groupMemberTarget[memberNodeID-fs.firstGroupMemberNodeID]
				}
				var member = memberAt(fs.Members, int(memberNodeID-fs.firstMemberNodeID))

				out = append(out, Assignment{
					ItemID:       itemID,
					MemberZone:   member.Zone,
					MemberSuffix: member.Suffix,
				})
			})
		}
		// Sort the portion just added to |out| under natural Assignment order.
		sort.Slice(out[sortFrom:], func(i, j int) bool {
			return compareAssignment(out[i+sortFrom], out[j+sortFrom]) < 0
		})
	}
	return out
}

// scaleAndRound returns |c * min(num / denom, 1)|, using integer math and rounding up.
func scaleAndRound(c, num, denom int) int {
	if num > denom {
		return c
	}
	if c *= num; c%denom != 0 {
		c += denom
	}
	return c / denom
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
