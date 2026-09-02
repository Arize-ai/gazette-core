package allocator

import (
	"slices"
	"strings"
)

// memberID identifies a Member independent of its index within State.Members.
type memberID struct {
	zone   string
	suffix string
}

// primaryEdge is a possible primary handoff: Item |itemID| currently has its
// primary Assignment on Member |from|, and is also replicated -- consistently
// -- by Member |to|, which could take over.
type primaryEdge struct {
	itemID string
	from   int
	to     int
}

// groupPrimaries is the transfer graph of one balance group: how many primary
// Assignments of the group each Member holds, which Members replicate any of
// it, and the handoffs available from each Member.
type groupPrimaries struct {
	counts []int32               // Primary Assignments of the group, by Member index.
	reach  []int32               // Assignments of any Slot, by Member index.
	edges  map[int][]primaryEdge // Available handoffs, keyed by the holding Member.
}

// rebalanceGroupPrimaries returns the primary handoffs which improve balance
// within each balance group whose primaries are unevenly spread, mapping an
// Item ID to the Member which should take over its primary Assignment. At most
// |maxSwaps| handoffs are returned across all groups: a handoff tears down and
// re-establishes an Item's replication pipeline, so skew is corrected
// gradually across convergence rounds rather than all at once.
//
// It returns nil -- doing no work at all, and allocating nothing -- when
// balancing is disabled or every group is already fair, which is the steady
// state of a healthy cluster.
func rebalanceGroupPrimaries(s *State, maxSwaps int) map[string]memberID {
	if maxSwaps <= 0 || s.MaxGroupPrimarySpread <= 1 {
		return nil
	}
	var tracked = trackedGroups(s)
	if len(tracked) == 0 {
		return nil
	}
	buildTransferGraphs(s, tracked)

	// Groups are walked in dense index order for determinism, so a shortage of
	// swap budget is spent on the same groups from one round to the next.
	var out = make(map[string]memberID)
	var used = make(map[string]bool)

	for _, gi := range sortedGroupIndices(tracked) {
		var g = tracked[gi]

		for maxSwaps > 0 {
			var path = g.augment(used)
			if path == nil || len(path) > maxSwaps {
				break // Group is optimal, or its correction won't fit our budget.
			}
			for _, e := range path {
				var member = memberAt(s.Members, e.to)
				out[e.itemID] = memberID{zone: member.Zone, suffix: member.Suffix}
				used[e.itemID] = true
			}
			// Only the path's endpoints change count: each intervening Member
			// hands off one primary and receives another.
			g.counts[path[0].from]--
			g.counts[path[len(path)-1].to]++
			maxSwaps -= len(path)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// trackedGroups returns a groupPrimaries, initialized with counts and reach,
// for each group whose primaries are spread wider than a single Assignment.
func trackedGroups(s *State) map[int32]*groupPrimaries {
	var out = make(map[int32]*groupPrimaries)

	for gi := int32(1); gi != int32(len(s.GroupNames)); gi++ {
		if s.groupPrimarySpread(gi) <= 1 {
			continue
		}
		var g = &groupPrimaries{
			counts: make([]int32, len(s.Members)),
			reach:  make([]int32, len(s.Members)),
			edges:  make(map[int][]primaryEdge),
		}
		for m := range s.Members {
			g.counts[m] = s.GroupPrimaryCount[s.groupCell(gi, m)]
			g.reach[m] = s.GroupMemberReach[s.groupCell(gi, m)]
		}
		out[gi] = g
	}
	return out
}

// buildTransferGraphs populates the edges of each tracked group, by walking
// Items joined with their Assignments. Only Items of a tracked group are
// examined, so an unlabeled or already-balanced cluster never reaches here.
func buildTransferGraphs(s *State, tracked map[int32]*groupPrimaries) {
	var it = LeftJoin{
		LenL: len(s.Items),
		LenR: len(s.Assignments),
		Compare: func(l, r int) int {
			return strings.Compare(itemAt(s.Items, l).ID, assignmentAt(s.Assignments, r).ItemID)
		},
	}
	for cur, ok := it.Next(); ok; cur, ok = it.Next() {
		var g = tracked[s.ItemGroups[cur.Left]]
		if g == nil {
			continue
		}
		var item = itemAt(s.Items, cur.Left)
		var asn = s.Assignments[cur.RightBegin:cur.RightEnd]

		// Identify the Item's current primary, and the Members which replicate
		// it consistently and could therefore take over. An inconsistent
		// replica is never a candidate: promoting it would trade availability
		// for fairness.
		var primary = -1
		var alternates []int

		for r := range asn {
			var a = assignmentAt(asn, r)
			var ind, found = s.Members.Search(MemberKey(s.KS, a.MemberZone, a.MemberSuffix))

			if !found {
				continue
			} else if a.Slot == 0 {
				primary = ind
			} else if s.IsConsistent(item, asn[r], asn) {
				alternates = append(alternates, ind)
			}
		}
		if primary == -1 {
			continue // No primary to hand off.
		}
		for _, to := range alternates {
			g.edges[primary] = append(g.edges[primary], primaryEdge{itemID: item.ID, from: primary, to: to})
		}
	}
}

// augment returns the shortest sequence of primary handoffs which moves one
// primary from a most-loaded Member of the group to a Member holding at least
// two fewer, or nil if no such sequence exists.
//
// A single handoff is not always sufficient. Given Items i1{A,B} and i2{A,B}
// with A primary for both, and i3{B,C} with B primary, counts are A=2 B=1 C=0:
// every single handoff from A merely trades the imbalance to B, so a rule
// which only considers one swap either refuses to act or oscillates forever.
// The two-hop rotation A ->(i1)-> B ->(i3)-> C reaches 1/1/1.
//
// Each accepted sequence strictly reduces the sum of squared per-Member counts
// by at least two, so repeated augmentation terminates. Finding no sequence
// proves the group is as even as its replica placement permits -- the Members
// reachable from its most-loaded Members form a tight cut -- so the caller
// stops rather than retrying.
func (g *groupPrimaries) augment(used map[string]bool) []primaryEdge {
	var hi int32 = -1
	for m := range g.counts {
		if g.reach[m] != 0 {
			hi = max32(hi, g.counts[m])
		}
	}
	if hi < 2 {
		return nil // No Member can hold two fewer than the maximum.
	}

	// Breadth-first from every most-loaded Member, so the first Member found
	// two or more below the maximum is reached by a shortest path.
	var (
		prev  = make(map[int]primaryEdge)
		seen  = make([]bool, len(g.counts))
		queue []int
	)
	for m := range g.counts {
		if g.reach[m] != 0 && g.counts[m] == hi {
			seen[m], queue = true, append(queue, m)
		}
	}

	for len(queue) != 0 {
		var u = queue[0]
		queue = queue[1:]

		if g.counts[u] <= hi-2 {
			var path []primaryEdge
			for v := u; ; {
				var e, ok = prev[v]
				if !ok {
					break
				}
				path = append(path, e)
				v = e.from
			}
			slices.Reverse(path)
			return path
		}
		for _, e := range g.edges[u] {
			if used[e.itemID] || seen[e.to] {
				continue
			}
			seen[e.to], prev[e.to] = true, e
			queue = append(queue, e.to)
		}
	}
	return nil
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

// sortedGroupIndices returns the dense group indices of |m| in ascending
// order, so that groups are always considered in the same sequence.
func sortedGroupIndices(m map[int32]*groupPrimaries) []int32 {
	var out = make([]int32, 0, len(m))
	for gi := range m {
		out = append(out, gi)
	}
	slices.Sort(out)
	return out
}
