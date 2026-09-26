package consumer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.gazette.dev/core/broker/client"
	pb "go.gazette.dev/core/broker/protocol"
	pc "go.gazette.dev/core/consumer/protocol"
	"go.gazette.dev/core/labels"
	"go.gazette.dev/core/message"
)

func TestReadMessages(t *testing.T) {
	var tf, shard, cleanup = newTestFixtureWithIdleShard(t)

	// Write a fixture to sourceB that's skipped by the checkpoint.
	var aa, _ = tf.pub.PublishCommitted(toSourceB, &testMessage{Key: "skipped"})
	<-aa.Done()

	var cp = pc.Checkpoint{
		Sources: map[pb.Journal]pc.Checkpoint_Source{
			sourceB.Name: {ReadThrough: aa.Response().Commit.End},
		},
	}

	// Write a fixture to sourceA that's skipped by spec MinOffset.
	aa, _ = tf.pub.PublishCommitted(toSourceA, &testMessage{Key: "also skipped"})
	<-aa.Done()
	shard.Spec().Sources[0].MinOffset = aa.Response().Commit.End

	var ch = make(chan EnvelopeOrError, 12)
	startReadingMessages(shard.ctx, shard, cp, ch)

	_, _ = tf.pub.PublishCommitted(toSourceA, &testMessage{Key: "one"})
	require.Equal(t, "one", (<-ch).Envelope.Message.(*testMessage).Key)
	_, _ = tf.pub.PublishCommitted(toSourceB, &testMessage{Key: "two"})
	require.Equal(t, "two", (<-ch).Envelope.Message.(*testMessage).Key)

	cleanup()
	require.Regexp(t, `framing.Unmarshal\(offset \d+\): context canceled`, (<-ch).Error)
}

func TestReadMessagesStopWithReaderContext(t *testing.T) {
	var tf, shard, cleanup = newTestFixtureWithIdleShard(t)
	defer cleanup()

	// Readers of a transaction loop iteration are scoped to a context derived
	// from the shard, so that restarting the loop (as happens on a write head
	// regression) tears them down rather than leaving them parked on the
	// abandoned channel while holding open their Read RPCs.
	var readCtx, readCancel = context.WithCancel(shard.ctx)

	var ch = make(chan EnvelopeOrError, 12)
	startReadingMessages(readCtx, shard, pc.Checkpoint{}, ch)

	var aa, _ = tf.pub.PublishCommitted(toSourceA, &testMessage{Key: "one"})
	<-aa.Done()
	require.Equal(t, "one", (<-ch).Envelope.Message.(*testMessage).Key)

	readCancel()

	// Every reader terminates, though the shard's own context is still live.
	for range shard.Spec().Sources {
		require.ErrorIs(t, (<-ch).Error, context.Canceled)
	}
	require.NoError(t, shard.ctx.Err())
}

func TestRecoverWriteHeadRegression(t *testing.T) {
	var _, shard, cleanup = newTestFixtureWithIdleShard(t)
	defer cleanup()

	_ = playAndComplete(t, shard)

	// Commit a checkpoint which reads both sources through non-zero offsets.
	var barrier = shard.store.StartCommit(shard, pc.Checkpoint{
		Sources: map[pb.Journal]pc.Checkpoint_Source{
			sourceA.Name: {ReadThrough: 9000},
			sourceB.Name: {ReadThrough: 7000},
		},
	}, nil)
	<-barrier.Done()
	require.NoError(t, barrier.Err())

	// sourceA's write head regressed behind our checkpoint, as it does after
	// `gazctl journals reset-head`.
	var cp, err = recoverWriteHeadRegression(shard, &client.OffsetExceedsWriteHeadError{
		Journal:   sourceA.Name,
		WriteHead: 1234,
	})
	require.NoError(t, err)

	// sourceA is rewound to the write head, and sourceB is carried through.
	require.Equal(t, int64(1234), cp.Sources[sourceA.Name].ReadThrough)
	require.Equal(t, int64(7000), cp.Sources[sourceB.Name].ReadThrough)

	// Crucially, the rewind is *durable*: a subsequent recovery cannot resurrect
	// the stale offset once appends have grown past it again.
	var restored pc.Checkpoint
	restored, err = shard.store.RestoreCheckpoint(shard)
	require.NoError(t, err)
	require.Equal(t, cp, restored)
}

func TestRecoverWriteHeadRegressionOfUncheckpointedJournal(t *testing.T) {
	var _, shard, cleanup = newTestFixtureWithIdleShard(t)
	defer cleanup()

	_ = playAndComplete(t, shard)

	// A journal absent from the checkpoint must still be bounded to the write
	// head. Otherwise the read would regress again on every restart, spinning
	// the transaction loop.
	var cp, err = recoverWriteHeadRegression(shard, &client.OffsetExceedsWriteHeadError{
		Journal:   sourceB.Name,
		WriteHead: 42,
	})
	require.NoError(t, err)
	require.Equal(t, int64(42), cp.Sources[sourceB.Name].ReadThrough)
}

func TestReadMessagesFailsWithUnknownJournal(t *testing.T) {
	var _, shard, cleanup = newTestFixtureWithIdleShard(t)
	defer cleanup()

	var ch = make(chan EnvelopeOrError, 12)
	shard.resolved.spec.Sources[1].Journal = "yyy/zzz"

	// Error is detected on first attempt at reading a message.
	startReadingMessages(shard.ctx, shard, pc.Checkpoint{}, ch)
	require.EqualError(t, (<-ch).Error,
		"fetching journal spec: named journal does not exist (yyy/zzz)")
}

func TestReadMessagesFailsWithBadFraming(t *testing.T) {
	var _, shard, cleanup = newTestFixtureWithIdleShard(t)
	defer cleanup()

	var ch = make(chan EnvelopeOrError, 12)
	shard.resolved.spec.Sources[1].Journal = shard.Spec().RecoveryLog()

	// Error is detected on first attempt at reading a message.
	startReadingMessages(shard.ctx, shard, pc.Checkpoint{}, ch)
	require.EqualError(t, (<-ch).Error, "determining framing: unrecognized "+labels.ContentType+
		" ("+labels.ContentType_RecoveryLog+")")
}

func TestShardTransitionsWithRecovery(t *testing.T) {
	// This test is invariant to running via JSONFileStore or a remote (memory) store. Try both.
	for _, spec := range []*pc.ShardSpec{
		makeShard(shardA),
		makeRemoteShard(shardA),
	} {
		var tf, cleanup = newTestFixture(t)

		tf.allocateShard(spec, localID)
		expectStatusCode(t, tf.state, pc.ReplicaStatus_PRIMARY)

		var res, err = tf.resolver.Resolve(ResolveArgs{Context: context.Background(), ShardID: shardA})
		require.NoError(t, err)

		// Write a partial transaction, which won't commit until after recovery.
		// This exercises replay across recovery boundaries.
		var replayPub = message.NewPublisher(tf.ajc, nil)
		_, err = replayPub.PublishUncommitted(toSourceA, &testMessage{Key: "re", Value: "play"})
		require.NoError(tf.t, err)

		// Run transactions of the primary (test fixture) publisher.
		runTransaction(tf, res.Shard, map[string]string{"foo": "bar", "one": "1"})
		runTransaction(tf, res.Shard, map[string]string{"foo": "baz", "two": "2"})
		verifyStoreAndEchoOut(t, res.Shard.(*shard),
			map[string]string{"foo": "baz", "one": "1", "two": "2"})

		// De-assign the shard, then re-assign as standby of a remote primary.
		res.Done()
		tf.allocateShard(spec)
		tf.allocateShard(spec, remoteID, localID)

		// Expect that status transitions through BACKFILL to STANDBY.
		expectStatusCode(t, tf.state, pc.ReplicaStatus_STANDBY)

		// Re-assign as shard primary.
		tf.allocateShard(spec, localID)
		expectStatusCode(t, tf.state, pc.ReplicaStatus_PRIMARY)

		res, err = tf.resolver.Resolve(ResolveArgs{Context: context.Background(), ShardID: shardA})
		require.NoError(t, err)

		// Now write ACK of |replayPub|.
		var intents, _ = replayPub.BuildAckIntents()
		for _, i := range intents {
			var aa = tf.ajc.StartAppend(pb.AppendRequest{Journal: i.Journal}, nil)
			_, _ = aa.Writer().Write(i.Intent)
			require.NoError(t, aa.Release())
			require.NoError(t, aa.Err())
		}

		// Expect the shard resumed from the former's store and message sequence.
		runTransaction(tf, res.Shard, map[string]string{"foo": "zing", "three": "3"})
		verifyStoreAndEchoOut(t, res.Shard.(*shard),
			map[string]string{"foo": "zing", "one": "1", "two": "2", "three": "3", "re": "play"})

		// Cleanup.
		res.Done()
		tf.allocateShard(spec)
		cleanup()
	}
}

func TestShardRecoveryLogDoesntExist(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	var spec = makeShard(shardA)
	spec.RecoveryLogPrefix = "does/not/exist"
	tf.allocateShard(spec, localID)

	require.Equal(t, "beginRecovery: fetching log spec: named journal does not exist "+
		"(does/not/exist/"+shardA+")",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(spec) // Cleanup.
}

func TestShardSourceDoesntExist(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	var spec = makeShard(shardA)
	spec.Sources[1].Journal = "xxx/yyy/zzz"
	tf.allocateShard(spec, localID)

	require.Equal(t, "runTransactions: readMessage: fetching journal spec: named journal does not exist "+
		"(xxx/yyy/zzz)",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(spec) // Cleanup.
}

func TestShardAppNewStoreError(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	tf.app.newStoreErr = errors.New("an error")
	tf.allocateShard(makeShard(shardA), localID)

	require.Equal(t, "completeRecovery: app.NewStore: an error",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(makeShard(shardA)) // Cleanup.
}

func TestShardAppNewMessageFails(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	tf.app.newMsgErr = errors.New("an error")
	var spec = makeShard(shardA)
	tf.allocateShard(spec, localID)

	_, _ = tf.pub.PublishCommitted(toSourceA, &testMessage{})

	require.Equal(t, "runTransactions: readMessage: newMessage: an error",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(spec) // Cleanup.
}

func TestShardStoreRestoreCheckpointFails(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	tf.app.restoreCheckpointErr = errors.New("an error")
	var spec = makeRemoteShard(shardA)
	tf.allocateShard(spec, localID)

	require.Equal(t, "completeRecovery: store.RestoreCheckpoint: an error",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(spec) // Cleanup.
}

func TestShardStoreStartCommitFails(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	tf.app.startCommitErr = errors.New("an error")
	var spec = makeRemoteShard(shardA)
	tf.allocateShard(spec, localID)

	var res, err = tf.resolver.Resolve(ResolveArgs{Context: context.Background(), ShardID: shardA})
	require.NoError(t, err)
	defer res.Done()

	runTransaction(tf, res.Shard, map[string]string{"foo": "bar"})

	require.Equal(t, "runTransactions: txnStartCommit: store.StartCommit: an error",
		expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(spec) // Cleanup.
}

func TestShardErrorsAreTruncatedIfLarge(t *testing.T) {
	var tf, cleanup = newTestFixture(t)
	defer cleanup()

	tf.app.newStoreErr = errors.New(strings.Repeat("e", MAX_ETCD_ERR_LEN+1))
	tf.allocateShard(makeShard(shardA), localID)

	var expect = fmt.Sprintf("completeRecovery: app.NewStore: %s", strings.Repeat("e", MAX_ETCD_ERR_LEN))
	expect = fmt.Sprintf("%s ...[truncated]", expect[:MAX_ETCD_ERR_LEN])

	require.Equal(t, expect, expectStatusCode(t, tf.state, pc.ReplicaStatus_FAILED).Errors[0])

	tf.allocateShard(makeShard(shardA)) // Cleanup.
}
