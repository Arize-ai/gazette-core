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
- `MemberValue`: User-defined Member with `ItemLimit() int` 
- `IsConsistentFn`: Determines if Item replicas are synchronized enough to allow reassignment
- `Decoder`: Decodes Etcd values into user-defined representations

### Flow Network
- `sparseFlowNetwork`: Models allocation as maximum flow problem
- Uses `sparse_push_relabel` algorithm to solve optimal assignments
- Item IDs sharing a logical "group" (eg partitions of a common topic, via
  `itemGroup`) are additionally balanced across Members *within* their group,
  through an intervening layer of Group-Member nodes -- see below.

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

## Group-aware balancing

Overall load balancing is necessary but not sufficient: a cluster's *total*
load can be perfectly even while a specific set of related Items -- eg the
16 partitions of one topic -- pile onto just one or two Members. This is
especially likely under repeated topology churn (eg a rolling Kubernetes
Deployment restart, where every Member gets a brand-new random identity):
each individual Member swap only reconsiders that Member's own orphaned
Items, so imbalance among any one logical group can accumulate indefinitely
even though the flow network is always re-solved to a legitimate maximum
assignment.

`itemGroup` infers a logical group from an Item ID: if the final
`/`-delimited path segment ends in decimal digits, the group is the ID with
that segment removed (`a-topic/part-003` groups with `a-topic`); otherwise
the ID is its own singleton group. Groups with only one Item are never
specially treated, since a single Item cannot itself cluster within a zone.

For every other (multi-Item) group, `sparseFlowNetwork` inserts a
**Group-Member** node for each `(zone, group, Member)` triple, sitting
between Zone-Item and Member nodes. Every Zone-Item of that group, within
that zone, is routed through the Group-Member node of its target Member
rather than directly to the Member. The Group-Member's single outgoing arc
is capacity-bound to that Member's fair share of the group within the zone
(`ceil(groupDemand / zoneMemberCount)`), enforcing balance as a hard flow
constraint rather than a mere ordering preference. Exactly like Member
fair-share (`buildMemberArc`), this cap is relaxed under sufficient network
"pressure" (see `groupMemberOverflowThreshold`) so that group fairness never
prevents an otherwise-achievable maximum assignment.

`groupDemand` is the group's Item *count* in the common multi-zone case,
since each Item ordinarily places just one replica per zone. But with only a
single zone, every replica of every Item -- not just one -- must land there,
so `groupDemand` is instead the group's total replication slots (`Item count
* DesiredReplication`). Using the raw Item count unconditionally understates
demand for `R > 1` in a single-zone cluster, which sets the cap far too low;
it's relaxed under pressure almost immediately, and because that relaxation
kicks in per-Group-Member rather than uniformly, one arbitrary Member ends up
absorbing the bulk of the group instead of the load spreading evenly.