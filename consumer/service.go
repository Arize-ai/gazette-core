package consumer

import (
	"context"

	"go.etcd.io/etcd/client/v3"
	"go.gazette.dev/core/allocator"
	pb "go.gazette.dev/core/broker/protocol"
	"go.gazette.dev/core/keyspace"
	"go.gazette.dev/core/server"
	"go.gazette.dev/core/task"
	"golang.org/x/net/trace"
	"google.golang.org/grpc"
)

// Service is the top-level runtime entity of a Gazette Consumer process.
// It drives local shard processing in response to allocator.State,
// powers shard resolution, and is also an implementation of ShardServer.
type Service struct {
	// Application served by the Service.
	App Application
	// Resolver of Service shards.
	Resolver *Resolver
	// Distributed allocator state of the service.
	State *allocator.State
	// Loopback connection which defaults to the local server, but is wired with
	// a pb.DispatchBalancer. Consumer applications may use Loopback to proxy
	// application-specific RPCs to peer consumer instance, after performing
	// shard resolution.
	Loopback *grpc.ClientConn
	// Journal client for use by consumer applications.
	Journals pb.RoutedJournalClient
	// Etcd client for use by consumer applications.
	Etcd *clientv3.Client

	// stoppingCh is closed when the Service is in the process of shutting down.
	stoppingCh chan struct{}
}

// NewService constructs a new Service of the Application, driven by allocator.State.
func NewService(app Application, state *allocator.State, rjc pb.RoutedJournalClient, lo *grpc.ClientConn, etcd *clientv3.Client) *Service {
	var svc = &Service{
		App:        app,
		State:      state,
		Loopback:   lo,
		Journals:   rjc,
		Etcd:       etcd,
		stoppingCh: make(chan struct{}),
	}
	svc.Resolver = NewResolver(state, func(item keyspace.KeyValue) *shard { return newShard(svc, item) })
	return svc
}

// QueueTasks to watch the Service KeySpace and serve any local assignments
// reflected therein, until the Context is cancelled or an error occurs.
// All local shards are gracefully stopped prior to return, even when exiting
// due to an error.
func (svc *Service) QueueTasks(tasks *task.Group, server *server.Server) {
	var watchCtx, watchCancel = context.WithCancel(context.Background())

	// Watch the Service KeySpace and manage local shard shards reflecting
	// the assignments of this consumer. Upon task completion, all shards
	// have been fully torn down.
	tasks.Queue("service.Watch", func() error {
		return svc.Resolver.watch(watchCtx, svc.Etcd)
	})

	// server.GracefulStop stops the server on task.Group cancellation,
	// after which the service.Watch is also cancelled.
	tasks.Queue("service.GracefulStop", func() error {
		<-tasks.Context().Done()

		// Signal the application that long-lived RPCs should stop,
		// so that our gRPC server may gracefully drain all ongoing RPCs.
		close(svc.stoppingCh)
		// Similarly, ensure all local shards are stopped. Under nominal
		// shutdown the allocator would already assure this, but if we're in the
		// process of crashing (eg due to Etcd partition) there may be remaining
		// local shards. Stopping them also cancels any related RPCs.
		svc.Resolver.stopServingLocalShards()

		server.BoundedGracefulStop()

		// Now that we're assured no current or future RPCs can be waiting
		// on a future KeySpace revision, instruct Watch to exit and block
		// until it does so.
		watchCancel()
		svc.Resolver.wg.Wait()

		// All shards (and any peer connections they may have held) have
		// fully torn down. Now we can tear down the loopback.
		return server.GRPCLoopback.Close()
	})
}

// Stopping returns a channel which signals when the Service is in the process
// of shutting down. Consumer applications with long-lived RPCs should use
// this signal to begin graceful cleanup of outstanding RPCs.
func (svc *Service) Stopping() <-chan struct{} { return svc.stoppingCh }

func addTrace(ctx context.Context, format string, args ...interface{}) {
	if tr, ok := trace.FromContext(ctx); ok {
		tr.LazyPrintf(format, args...)
	}
}
