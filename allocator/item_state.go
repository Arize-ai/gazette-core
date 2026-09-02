package allocator

import (
	"sort"

	"go.etcd.io/etcd/client/v3"
	"go.gazette.dev/core/keyspace"
)

// itemState is an extracted representation of an Item and a collection of
// desired changes to its Assignments.
type itemState struct {
	global *State

	// balancePrimaries enables group-aware primary selection. It is false
	// unless AllocateArgs.MaxPrimarySwapsPerRound is non-zero, in which case
	// every primary decision below reduces to its prior behavior.
	balancePrimaries bool
	// desiredPrimary is the Member which should take over this Item's primary
	// Assignment, as determined by rebalanceGroupPrimaries, or the zero value
	// if its primary should stay where it is. Set per Item by converge.
	desiredPrimary memberID

	item    int                // Index of current Item within |global.Items|.
	current keyspace.KeyValues // Sub-slice of Item's current Assignments within |global.Assignments|.

	add     []Assignment       // Assignments we seek to add.
	remove  keyspace.KeyValues // Assignments we seek to remove.
	reorder keyspace.KeyValues // Assignments we seek to keep, and potentially re-order.
}

// init initializes the itemState by deriving the set of added, removed, and reordered Assignments
// given |current| and |desired|.
func (s *itemState) init(item int, current keyspace.KeyValues, desired []Assignment) {
	*s = itemState{
		global:           s.global,
		balancePrimaries: s.balancePrimaries,

		item:    item,
		current: current,

		add:     s.add[:0],
		remove:  s.remove[:0],
		reorder: s.reorder[:0],
	}

	var i, j, nextSlot int

	// Initialize |nextSlot| to be greater than any Slot in use by any |current| Assignment.
	for _, a := range s.current {
		if s := a.Decoded.(Assignment).Slot + 1; s > nextSlot {
			nextSlot = s
		}
	}

	// Jointly walk |current| and |desired| on natural Assignment order
	// to determine desired add/remove/reorder edits.
	for i != len(s.current) && j != len(desired) {
		var a = assignmentAt(s.current, i)

		if c := compareAssignment(a, desired[j]); c > 0 {
			var a = desired[j]
			a.Slot, nextSlot = nextSlot, nextSlot+1
			s.add = append(s.add, a)
			j++
		} else if c < 0 {
			s.remove = append(s.remove, s.current[i])
			i++
		} else {
			s.reorder = append(s.reorder, s.current[i])
			i++
			j++
		}
	}
	for ; i != len(s.current); i++ {
		s.remove = append(s.remove, s.current[i])
	}
	for ; j != len(desired); j++ {
		var a = desired[j]
		a.Slot, nextSlot = nextSlot, nextSlot+1
		s.add = append(s.add, a)
	}
}

// constrainRemovals prunes Assignments from |s.remove| which would otherwise violate
// constraints, moving them to |s.reorder|.
func (s *itemState) constrainRemovals() {
	// Order |s.remove| on decreasing member load ratio
	// (the ratio of the member's total Assignments, vs its item limit).
	sort.Slice(s.remove, func(i, j int) bool {
		var ri = s.global.memberLoadRatio(s.remove[i], s.global.MemberTotalCount)
		var rj = s.global.memberLoadRatio(s.remove[j], s.global.MemberTotalCount)
		return ri > rj
	})
	var item = itemAt(s.global.Items, s.item)

	// Determine the current number of consistent item Assignments.
	var n int
	for _, a := range s.current {
		if s.global.IsConsistent(item, a, s.current) {
			n += 1
		}
	}
	// Release Assignments in decreasing order of member load ratio. Halt if
	// releasing an Assignment would violate the Item replication guarantee.
	var limit int

	for r := item.DesiredReplication(); n >= r && limit != len(s.remove); limit++ {
		if c := s.global.IsConsistent(item, s.remove[limit], s.current); c && n == r {
			break // We cannot remove this assignment without breaking n >= r.
		} else if c {
			n -= 1
		}
	}

	// Truncate removals to |limit|. Append the rest to |reorder|,
	// as we will not be removing these Assignments.
	s.reorder = append(s.reorder, s.remove[limit:]...)
	s.remove = s.remove[:limit]
}

// constrainReorders updates the ordering of |s.reorders| to ensure the best
// Assignment is selected as primary (which is always s.reorders[0]).
func (s *itemState) constrainReorders() {
	// Order |s.reorder| on ascending Assignment Slot.
	sort.Slice(s.reorder, func(i, j int) bool {
		return assignmentAt(s.reorder, i).Slot < assignmentAt(s.reorder, j).Slot
	})
	// The ordering is trivially satisfied iff there are no Assignments,
	// and is otherwise satisfied iff there is a current primary.
	if len(s.reorder) == 0 || assignmentAt(s.reorder, 0).Slot == 0 {
		return
	}
	var item = itemAt(s.global.Items, s.item)

	// There is no current primary. Select an assignment to promote, preferring:
	// a) Assignments which are currently consistent, and then
	// b) Assignments having a lower primary load ratio
	//    (the ratio of the member's primary Assignments, vs its item limit).

	var primary = struct {
		index        int
		isConsistent bool
		groupLoad    int32
		loadRatio    float32
		kv           keyspace.KeyValue
	}{index: -1}

	for i := range s.reorder {
		var c = s.global.IsConsistent(item, s.reorder[i], s.current)
		var r = s.global.memberLoadRatio(s.reorder[i], s.global.MemberPrimaryCount)
		var g = s.groupPrimaryLoad(assignmentAt(s.reorder, i))

		if primary.index == -1 ||
			c == true && primary.isConsistent == false ||
			c == primary.isConsistent && (g < primary.groupLoad ||
				g == primary.groupLoad && r < primary.loadRatio) {

			primary.index, primary.isConsistent, primary.kv = i, c, s.reorder[i]
			primary.groupLoad, primary.loadRatio = g, r
		}
	}

	// Shift elements [0, primary.index) to the right, by one.
	copy(s.reorder[1:primary.index+1], s.reorder[:primary.index])
	s.reorder[0] = primary.kv
}

// groupPrimaryLoad returns the number of primary Assignments of this Item's
// balance group already held by |a|'s Member. It returns zero -- making it
// inert as a comparison key -- when primary balancing is disabled or the Item
// declares no group.
func (s *itemState) groupPrimaryLoad(a Assignment) int32 {
	var gi = s.global.ItemGroups[s.item]
	if !s.balancePrimaries || gi == 0 {
		return 0
	}
	var ind, found = s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix))
	if !found {
		return 0
	}
	return s.global.GroupPrimaryCount[s.global.groupCell(gi, ind)]
}

// constrainAddPrimary permutes Slot values among |s.add| so that Slot 0 falls
// to the Member holding the fewest primary Assignments of this Item's balance
// group. It acts only when Slot 0 is itself being added -- so no existing
// primary is displaced and no handoff occurs -- and is inert for an Item which
// declares no group.
//
// Without it, Slots follow the order in which desired Assignments were solved,
// which is lexicographic on (zone, suffix). Every partition of a newly created
// topic therefore hands its primary to the same Member, which is the dominant
// source of primary skew.
func (s *itemState) constrainAddPrimary() {
	var gi = s.global.ItemGroups[s.item]
	if !s.balancePrimaries || gi == 0 || len(s.add) < 2 {
		return
	}
	var zero = -1
	for i := range s.add {
		if s.add[i].Slot == 0 {
			zero = i
			break
		}
	}
	if zero == -1 {
		return // The Item keeps a current primary; nothing to choose.
	}

	var best = zero
	for i := range s.add {
		if i != zero && s.betterGroupPrimary(gi, s.add[i], s.add[best]) {
			best = i
		}
	}
	s.add[zero].Slot, s.add[best].Slot = s.add[best].Slot, s.add[zero].Slot
}

// betterGroupPrimary returns whether |a| is a more suitable primary than |b|
// for an Item of group |gi|, preferring the Member holding fewer of the
// group's primaries, then the Member with the lower overall primary load
// ratio, and finally the lower Member key so the choice is deterministic.
func (s *itemState) betterGroupPrimary(gi int32, a, b Assignment) bool {
	var ai, aok = s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix))
	var bi, bok = s.global.Members.Search(MemberKey(s.global.KS, b.MemberZone, b.MemberSuffix))

	if !aok {
		return false
	} else if !bok {
		return true
	}

	var ac = s.global.GroupPrimaryCount[s.global.groupCell(gi, ai)]
	var bc = s.global.GroupPrimaryCount[s.global.groupCell(gi, bi)]

	if ac != bc {
		return ac < bc
	} else if ar, br := s.global.memberPrimaryRatio(ai), s.global.memberPrimaryRatio(bi); ar != br {
		return ar < br
	}
	return ai < bi
}

// constrainAdds prunes Assignments from |s.add| which would otherwise violate constraints.
func (s *itemState) constrainAdds() {
	for i := 0; i != len(s.add); {
		var a = s.add[i]

		var ind, found = s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix))
		if !found {
			panic("member not found")
		}

		if s.global.memberEffectiveLimit(ind) <= s.global.MemberTotalCount[ind] {
			// Addition would violate member's effective limit. Remove this Assignment.
			copy(s.add[i:], s.add[i+1:])
			s.add = s.add[:len(s.add)-1]
		} else {
			i++
		}
	}
}

// buildRemoveOps adds operations to |txn| removing each of the Assignments in |s.remove|.
func (s *itemState) buildRemoveOps(txn checkpointTxn) {
	for i, r := range s.remove {
		// Verify the Item (and Assignment itself) have not changed. Otherwise, the
		// Item Replication may have increased (and this removal could violate it).
		if i == 0 {
			txn.If(modRevisionUnchanged(s.global.Items[s.item]))
		}
		txn.If(modRevisionUnchanged(r))
		// Delete the Assignment to remove.
		txn.Then(clientv3.OpDelete(string(r.Raw.Key)))

		// Update to reflect the member's total count has decreased.
		var a = assignmentAt(s.remove, i)
		if ind, found := s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix)); found {
			if a.Slot == 0 {
				s.global.MemberPrimaryCount[ind] -= 1
			}
			s.global.MemberTotalCount[ind] -= 1
		}
		// We allow for !found (and do not panic) to gracefully handle assignments
		// which somehow linger after their corresponding member is deleted (note
		// that in practice all keys of an Etcd lease are deleted in a single txn).

		allocatorAssignmentRemovedTotal.Inc()
	}
}

// buildPromoteOps adds operations to |txn| which, if required,
// promote a current Assignment to primary, if required.
func (s *itemState) buildPromoteOps(txn checkpointTxn) {
	if len(s.reorder) == 0 {
		return // No Assignments to promote.
	} else if a := assignmentAt(s.reorder, 0); a.Slot == 0 {
		return // Assignment is already primary.
	} else {
		a.Slot = 0 // Promote to Primary.

		// Update to reflect the member's primary count has increased.
		if ind, found := s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix)); found {
			s.global.MemberPrimaryCount[ind] += 1
			s.creditGroupPrimary(ind, 1)
		}
		// Like buildRemoveOps, we allow for the possibility of !found (and do not
		// panic). Note that a member without a member key will have an infinite
		// load ratio, and is therefore promoted only as a last resort.
		s.buildMoveOps(txn, s.reorder[0], a)

		allocatorAssignmentPackedTotal.Inc()
	}
}

// buildAddOps adds operations to |txn| to create new Assignments for each of |s.add|.
func (s *itemState) buildAddOps(txn checkpointTxn) {
	for _, a := range s.add {
		var ind, found = s.global.Members.Search(MemberKey(s.global.KS, a.MemberZone, a.MemberSuffix))
		if !found {
			panic("member not found")
		}

		// Verify the Member has not changed. Otherwise, its ItemLimit may have decreased
		// (and this addition could violate it).
		txn.If(modRevisionUnchanged(s.global.Members[ind]))
		// Put an Assignment with an empty value under the Member's Lease.
		txn.Then(clientv3.OpPut(AssignmentKey(s.global.KS, a), "",
			clientv3.WithLease(clientv3.LeaseID(s.global.Members[ind].Raw.Lease))))

		// Update to reflect the member's total count (and potentially primary count) has increased.
		// Crediting the group as we go is what lets successive Items of one
		// group, converged in a single pass, each pick a different primary.
		if a.Slot == 0 {
			s.global.MemberPrimaryCount[ind] += 1
			s.creditGroupPrimary(ind, 1)
		}
		s.global.MemberTotalCount[ind] += 1

		allocatorAssignmentAddedTotal.Inc()
	}
}

// creditGroupPrimary adjusts the primary count of this Item's balance group
// for Member |ind| by |delta|. It is a no-op for an ungrouped Item.
func (s *itemState) creditGroupPrimary(ind int, delta int32) {
	if gi := s.global.ItemGroups[s.item]; gi != 0 {
		s.global.GroupPrimaryCount[s.global.groupCell(gi, ind)] += delta
	}
}

// buildSwapPrimaryOps exchanges the Slots of the Item's current primary and
// the staying Assignment of s.desiredPrimary, and reports whether it did so.
//
// Both halves are issued within one transaction checkpoint, and therefore one
// Etcd transaction. That is essential rather than merely tidy: the Slot is part
// of the Assignment key, so a promotion is a key move and not a value update.
// Issuing the promotion without its matching demotion would leave the Item with
// two Slot 0 Assignments, which readers resolve to whichever key sorts last
// (see ext.Init) while both Members independently believe they are primary.
//
// The four keys involved are distinct -- the key carries both Member and Slot,
// so no key is both put and deleted -- which is what makes the exchange
// expressible as a single transaction at all.
func (s *itemState) buildSwapPrimaryOps(txn checkpointTxn) bool {
	if s.desiredPrimary == (memberID{}) || len(s.reorder) == 0 {
		return false
	}
	var cur = assignmentAt(s.reorder, 0)
	if cur.Slot != 0 {
		return false // No current primary: constrainReorders promotes instead.
	} else if cur.MemberZone == s.desiredPrimary.zone && cur.MemberSuffix == s.desiredPrimary.suffix {
		return false // Already where we want it.
	}
	var item = itemAt(s.global.Items, s.item)

	for k := 1; k != len(s.reorder); k++ {
		var next = assignmentAt(s.reorder, k)

		if next.MemberZone != s.desiredPrimary.zone || next.MemberSuffix != s.desiredPrimary.suffix {
			continue
		} else if !s.global.IsConsistent(item, s.reorder[k], s.current) {
			return false // Never promote a replica which isn't caught up.
		}
		var curKV, nextKV = s.reorder[0], s.reorder[k]
		cur.Slot, next.Slot = next.Slot, cur.Slot

		txn.If(modRevisionUnchanged(curKV), modRevisionUnchanged(nextKV)).
			Then(
				clientv3.OpDelete(string(curKV.Raw.Key)),
				clientv3.OpDelete(string(nextKV.Raw.Key)),
				clientv3.OpPut(AssignmentKey(s.global.KS, cur), string(curKV.Raw.Value),
					clientv3.WithLease(clientv3.LeaseID(curKV.Raw.Lease))),
				clientv3.OpPut(AssignmentKey(s.global.KS, next), string(nextKV.Raw.Value),
					clientv3.WithLease(clientv3.LeaseID(nextKV.Raw.Lease))),
			)

		if ind, found := s.global.Members.Search(MemberKey(s.global.KS, cur.MemberZone, cur.MemberSuffix)); found {
			s.global.MemberPrimaryCount[ind] -= 1
			s.creditGroupPrimary(ind, -1)
		}
		if ind, found := s.global.Members.Search(MemberKey(s.global.KS, s.desiredPrimary.zone, s.desiredPrimary.suffix)); found {
			s.global.MemberPrimaryCount[ind] += 1
			s.creditGroupPrimary(ind, 1)
		}
		allocatorPrimarySwapTotal.Inc()
		return true
	}
	return false // The desired Member is no longer a staying replica.
}

// buildPackOps adds operations to |txn| which shift the Slot of up to one
// current Assignment down to a lower and contiguous Slot index.
func (s *itemState) buildPackOps(txn checkpointTxn) {
	for i := range s.reorder {
		if i == 0 {
			continue // Case handled by buildPromoteOps.
		} else if a := assignmentAt(s.reorder, i); a.Slot != i {
			a.Slot = i
			s.buildMoveOps(txn, s.reorder[i], a)
			allocatorAssignmentPackedTotal.Inc()
			break
		}
	}
}

// buildMoveOps atomically moves the |cur| Assignment to a new key.
func (s *itemState) buildMoveOps(txn checkpointTxn, cur keyspace.KeyValue, a Assignment) {
	// Atomic move of same value from current Assignment key, to a new one under the current Lease.
	txn.If(modRevisionUnchanged(cur)).
		Then(
			clientv3.OpDelete(string(cur.Raw.Key)),
			clientv3.OpPut(AssignmentKey(s.global.KS, a), string(cur.Raw.Value),
				clientv3.WithLease(clientv3.LeaseID(cur.Raw.Lease))))
}

// constrainAndBuildOps applies all constraints, and then applies resulting
// add, remove, promotion, and packing operations to |txn|.
func (s *itemState) constrainAndBuildOps(txn checkpointTxn) error {
	s.constrainRemovals()
	s.constrainReorders()
	s.constrainAdds()
	s.constrainAddPrimary()

	s.buildAddOps(txn)
	s.buildRemoveOps(txn)
	s.buildPromoteOps(txn)

	// An Item which is otherwise moving this round is left alone: it has no
	// spare Slot bookkeeping to give, and deferring is free hysteresis, since
	// the handoff is re-proposed on a later round if still worthwhile.
	if len(s.add) == 0 && len(s.remove) == 0 {
		if !s.buildSwapPrimaryOps(txn) {
			s.buildPackOps(txn)
		}
	}
	return txn.Checkpoint()
}
