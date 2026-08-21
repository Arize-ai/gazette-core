# Fragment

The fragment package provides journal fragment management for Gazette brokers. It handles the mapping of journal offsets to protocol.Fragments and manages local/remote journal content through various storage backends.

## What it does

- **Fragment Lifecycle**: Manages fragments from creation (Spool) through persistence to storage backends
- **Storage Abstraction**: Provides unified interface for file://, s3://, gcs://, and azure:// storage schemes
- **Fragment Indexing**: Maintains queryable indexes of local and remote fragments with offset-to-fragment mapping
- **Replication Support**: Handles fragment spooling during broker replication operations

## Architecture

### Core Types

- **Fragment**: Wrapper around `protocol.Fragment` with optional local file backing
- **Spool**: In-progress fragment being written during replication, with compression and checksumming
- **Index**: Queryable index mapping journal offsets to best-covering fragments
- **CoverSet**: Ordered collection of fragments with overlap resolution
- **Persister**: Asynchronous background service for persisting completed spools to storage

### Storage Backends

The package abstracts over multiple storage providers through a common `backend` interface:

- **File System** (`store_fs.go`): Local filesystem storage
- **Amazon S3** (`store_s3.go`): AWS S3 compatible storage  
- **Google Cloud Storage** (`store_gcs.go`): GCS object storage
- **Azure Blob** (`store_azure.go`): Azure Blob Storage

Each backend implements operations for signing URLs, checking existence, opening, persisting, listing, and removing fragments.

### Fragment Spooling

During journal replication:

1. **Spool Creation**: New `Spool` created for incoming writes
2. **Content Buffering**: Writes accumulated with compression and SHA1 checksumming
3. **Commit/Rollback**: Transactional operations extend or revert fragment content
4. **Completion**: Finished spools queued for background persistence

### Write Head Regression

`Index.Query` ordinarily *blocks* a read of an offset ahead of the index. That covers
the race between delayed persistence to a fragment store and hand-off of a journal to
a new broker, where the broker serving the read isn't yet aware of a fragment which is
being uploaded or is held in a peer's spool.

A write head which moved *backward*, as `gazctl journals reset-head` does, is
indistinguishable from that race at first glance — but blocking is wrong, because new
appends will never align with the message framing at the requested offset, and the
reader would eventually be served mid-message data.

`Query` separates the two by requiring that the condition persist for
`writeHeadRegressionGrace` after the index's first remote refresh. It then returns
`OFFSET_NOT_YET_AVAILABLE` carrying the current write head, which `broker/client`
surfaces as an `OffsetExceedsWriteHeadError` so the reader can restart there.

### Persistence

The `Persister` manages asynchronous fragment persistence:

- Primary replicas attempt immediate persistence
- Secondary replicas queue spools for later persistence
  - In the common case this is a cheap existence check
  - If the primary broker has crashed, it ensures the fragment is persisted
- Failed persistence operations are retried with backoff
- Supports multiple storage backends

## Key Operations

- **Fragment Queries**: Map journal offsets to covering fragments
- **Spool Management**: Handle transactional fragment construction
- **Store Operations**: Abstract storage operations across backends
- **Index Maintenance**: Keep fragment indexes current with storage state

## Usage

The fragment package is used internally by broker services for:

- Serving read requests by locating appropriate fragments
- Managing fragment creation during journal replication
- Persisting completed fragments to configured storage
- Maintaining indexes for efficient fragment lookup