// Package allocator implements a distributed algorithm for assigning a number
// of "Items" across a number of "Members", where each Member runs an instance of
// the Allocator. Items and Members may come and go over time; each may have
// constraints on desired replication and assignment limits which must be
// satisfied, and replicas may be placed across distinct failure Zones.
// Allocator coordinates through Etcd, and uses a greedy, incremental maximum-
// flow solver to quickly determine minimal re-Assignments which best balance
// Items across Members (subject to constraints).
package allocator

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	allocatorAssignmentAddedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gazette_allocator_assignment_added_total",
		Help: "Cumulative number of item / member assignments added by the allocator.",
	})
	allocatorAssignmentPackedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gazette_allocator_assignment_packed_total",
		Help: "Cumulative number of item / member assignments packed by the allocator.",
	})
	allocatorAssignmentRemovedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gazette_allocator_assignment_removed_total",
		Help: "Cumulative number of item / member assignments removed by the allocator.",
	})
	allocatorConvergeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gazette_allocator_converge_total",
		Help: "Cumulative number of converge iterations.",
	})
	allocatorMaxFlowRuntimeSeconds = promauto.NewHistogram(prometheus.HistogramOpts{
		Name: "gazette_allocator_max_flow_runtime_seconds",
		Help: "Duration required to re-solve for maximum assignment.",
	})
	allocatorNumItemSlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_desired_replication_slots",
		Help: "Number of desired item replication slots summed across all items.",
	})
	allocatorNumItems = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_items",
		Help: "Number of items known to the allocator.",
	})
	allocatorNumMembers = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_members",
		Help: "Number of members known to the allocator.",
	})
	allocatorMemberAssignments = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gazette_allocator_member_assignments",
		Help: "Number of assignments of any slot held by each member.",
	}, []string{"zone", "suffix"})
	allocatorMemberPrimaries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "gazette_allocator_member_primaries",
		Help: "Number of primary (slot zero) assignments held by each member.",
	}, []string{"zone", "suffix"})
	allocatorNumGroups = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_balance_groups",
		Help: "Number of balance groups declared by items.",
	})
	allocatorGroupPrimarySpreadMax = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_balance_group_primary_spread_max",
		Help: "Largest difference in primary assignments of one balance group held by any member replicating part of it. One or less is fair.",
	})
	allocatorGroupPrimaryShareMax = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gazette_allocator_balance_group_primary_share_max",
		Help: "Largest ratio of a member's primary assignments of one balance group to an even share of that group. One is fair; N members' worth of skew reads as N.",
	})
	allocatorPrimarySwapTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gazette_allocator_primary_swap_total",
		Help: "Cumulative number of primary assignments exchanged to rebalance a balance group. Must flatten once settled; a sustained rate indicates oscillation.",
	})
)
