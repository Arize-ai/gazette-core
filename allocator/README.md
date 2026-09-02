# Allocator

Distributed algorithm for assigning a set of "Items" across a pool of "Members" with replication and zone constraints.

## What it does

The allocator implements a distributed, fault-tolerant system for assigning Items to Members across multiple availability zones. Each Member runs an instance of the Allocator which coordinates through Etcd to:

- Assign Items to Members respecting desired replication counts
- Distribute replicas across failure zones for high availability  
- Balance load evenly across Members within capacity limits
- Maintain consistency constraints during reassignments
- Perform minimal incremental updates when topology changes

## How it fits into Gazette

The allocator is used by both the broker and consumer frameworks:

- **Brokers**: Assigns journal shards to broker instances across zones
- **Consumers**: Assigns consumer shards to consumer instances across zones

It provides the core scheduling intelligence that keeps Gazette services highly available and load-balanced.

## Essential Types

### Core Entities
- `Item`: Something to be assigned (journal, shard, etc.) with desired replication
- `Member`: An instance that can be assigned Items, with capacity limits  
- `Assignment`: A specific Item-to-Member assignment with slot ordering
- `State`: Extracted view of current allocation topology from Etcd KeySpace

### Key Interfaces
- `ItemValue`: User-defined Item with `DesiredReplication() int`
- `ItemGroupValue`: *Optional* Item interface declaring a `BalanceGroup() string` -- see "Balance groups"
- `MemberValue`: User-defined Member with `ItemLimit() int` 
- `IsConsistentFn`: Determines if Item replicas are synchronized enough to allow reassignment
- `Decoder`: Decodes Etcd values into user-defined representations

### Flow Network
- `sparseFlowNetwork`: Models allocation as maximum flow problem
- Uses `sparse_push_relabel` algorithm to solve optimal assignments

## Brief Architecture

The allocator uses a **leader-follower** model where one Member acts as leader and makes allocation decisions:

1. **State Observation**: All Members observe shared Etcd KeySpace containing Items, Members, and current Assignments

2. **Leadership Election**: Leader is the Member with lowest `(CreateRevision, Key)` tuple

3. **Flow Network Solving**: Leader models allocation as maximum flow network and solves for optimal assignments using push/relabel algorithm

4. **Incremental Convergence**: Leader applies minimal changes through batched Etcd transactions, respecting consistency constraints

5. **Session Management**: Members announce themselves with Etcd leases and gracefully shutdown by zeroing their ItemLimit

The algorithm prioritizes:
- **Stability**: Minimal reassignments when topology changes
- **Balance**: Even distribution across Members and zones  
- **Availability**: Maintains replication during reassignments
- **Performance**: Incremental updates scale linearly with Items

## Balance groups

Balancing each Member's *total* Item count is necessary but not sufficient. A
maximum assignment can place every partition of one topic -- and every one of
their primaries -- onto a single Member while each Member's total count remains
perfectly even. Since the Slot 0 (primary) replica bears extra load, that
Member becomes a bottleneck no amount of total-count balancing will relieve.

An Item may therefore declare a **balance group** through the optional
`ItemGroupValue` interface. Items of a common group are balanced against one
another, in addition to the existing total-count balancing. `*pb.JournalSpec`
implements it from the `app.gazette.dev/balance-group` label; consumer
`ShardSpec`s deliberately do not implement it, so consumer allocation is
unchanged.

The group value is opaque and matched exactly, so specifications under
unrelated prefixes which share a value form one group. Prefer qualified values
(`tracing/spans` rather than `spans`) unless grouping across prefixes is
intended. An absent or empty value means the Item is ungrouped and is scheduled
exactly as it was before groups existed -- so a deployment which labels nothing
is unaffected.

`State` extracts per-group bookkeeping on every observation, whether or not any
balancing is enabled: `GroupNames` (dense, index zero being the ungrouped
sentinel), `ItemGroups`, and the row-major `GroupPrimaryCount` and
`GroupMemberReach` matrices. `MaxGroupPrimarySpread` summarizes the worst
group's imbalance and gates rebalancing. `GroupMemberReach` matters because a
Member can only be primary for an Item it already replicates -- so spread is
measured only over Members which replicate part of the group, since counting a
Member with no stake would report an imbalance no reassignment could close.

### Primary balancing

Primary (Slot 0) selection is deliberately decoupled from replica placement:
the flow network decides *which Members replicate* an Item, and primary
balancing only decides *which of those replicas is primary*. Two mechanisms,
both no-ops unless `AllocateArgs.MaxPrimarySwapsPerRound` is non-zero:

- `itemState.constrainAddPrimary` orders Slot assignment among an Item's *new*
  Assignments, so a newly created topic spreads its primaries instead of
  handing them all to the lexicographically-first Member. Nothing is demoted,
  so this costs no churn at all.
- `rebalanceGroupPrimaries` (`group_primary.go`) corrects *existing* skew. It
  searches the transfer graph -- Member, to Items it is primary for, to those
  Items' other replicas -- for an augmenting path to an under-loaded Member. A
  single best swap is not always enough: some topologies need a multi-hop
  rotation of primaries across several Items, and a naive one-swap rule either
  deadlocks or oscillates. Each accepted path strictly reduces the sum of
  squared per-Member counts, so the search terminates, and the absence of any
  path proves the group is already optimal.

A primary handoff tears down and re-establishes a journal's replication
pipeline, so swaps are bounded per round and skew is corrected gradually.
`itemState.buildSwapPrimaryOps` exchanges both Slots within a single
`checkpointTxn` checkpoint, so an Item is never observed with two Slot 0
Assignments.
