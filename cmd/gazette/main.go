package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"go.gazette.dev/core/allocator"
	"go.gazette.dev/core/broker"
	"go.gazette.dev/core/broker/fragment"
	"go.gazette.dev/core/broker/http_gateway"
	pb "go.gazette.dev/core/broker/protocol"
	mbp "go.gazette.dev/core/mainboilerplate"
	"go.gazette.dev/core/server"
	"go.gazette.dev/core/task"
)

const iniFilename = "gazette.ini"

// Config is the top-level configuration object of a Gazette broker.
var Config = new(struct {
	Broker struct {
		mbp.ServiceConfig
		Limit             uint32        `long:"limit" env:"LIMIT" default:"1024" description:"Maximum number of Journals the broker will allocate"`
		FileRoot          string        `long:"file-root" env:"FILE_ROOT" description:"Local path which roots file:// fragment stores (optional)"`
		MaxAppendRate     uint32        `long:"max-append-rate" env:"MAX_APPEND_RATE" default:"0" description:"Max rate (in bytes-per-sec) that any one journal may be appended to. If zero, there is no max rate"`
		MaxReplication    uint32        `long:"max-replication" env:"MAX_REPLICATION" default:"9" description:"Maximum effective replication of any one journal, which upper-bounds its stated replication."`
		MinAppendRate     uint32        `long:"min-append-rate" env:"MIN_APPEND_RATE" default:"65536" description:"Min rate (in bytes-per-sec) at which a client may stream Append RPC content. RPCs unable to sustain this rate are aborted"`
		DisableStores     bool          `long:"disable-stores" env:"DISABLE_STORES" description:"Disable use of any configured journal fragment stores. The broker will neither list or persist remote fragments, and all data is discarded on broker exit."`
		WatchDelay        time.Duration `long:"watch-delay" env:"WATCH_DELAY" default:"30ms" description:"Delay applied to the application of watched Etcd events. Larger values amortize the processing of fast-changing Etcd keys."`
		DisableSignedUrls bool          `long:"disable-signed-urls" env:"DISABLE_SIGNED_URLS" description:"When a signed URL is requested, return an unsigned URL instead. This is useful when clients do not require the signing."`
	} `group:"Broker" namespace:"broker" env-namespace:"BROKER"`

	Etcd struct {
		mbp.EtcdConfig
		Prefix string `long:"prefix" env:"PREFIX" default:"/gazette/cluster" description:"Etcd base prefix for broker state and coordination"`
	} `group:"Etcd" namespace:"etcd" env-namespace:"ETCD"`

	Log         mbp.LogConfig         `group:"Logging" namespace:"log" env-namespace:"LOG"`
	Diagnostics mbp.DiagnosticsConfig `group:"Debug" namespace:"debug" env-namespace:"DEBUG"`
})

type cmdServe struct{}

func (cmdServe) Execute(args []string) error {
	defer mbp.InitDiagnosticsAndRecover(Config.Diagnostics)()
	mbp.InitLog(Config.Log)

	log.WithFields(log.Fields{
		"config":    Config,
		"version":   mbp.Version,
		"buildDate": mbp.BuildDate,
	}).Info("broker configuration")
	pb.RegisterGRPCDispatcher(Config.Broker.Zone)

	// Bind our server listener, grabbing a random available port if Port is zero.
	var srv, err = server.New("", Config.Broker.Port)
	mbp.Must(err, "building Server instance")

	// If a file:// root was provided, ensure it exists and apply it.
	if Config.Broker.FileRoot != "" {
		_, err = os.Stat(Config.Broker.FileRoot)
		mbp.Must(err, "configured local file:// root failed")
		fragment.FileSystemStoreRoot = Config.Broker.FileRoot
	}

	broker.MinAppendRate = int64(Config.Broker.MinAppendRate)
	broker.MaxAppendRate = int64(Config.Broker.MaxAppendRate)
	pb.MaxReplication = int32(Config.Broker.MaxReplication)
	fragment.DisableStores = Config.Broker.DisableStores
	fragment.DisableSignedUrls = Config.Broker.DisableSignedUrls

	var (
		lo   = pb.NewJournalClient(srv.GRPCLoopback)
		etcd = Config.Etcd.MustDial()
		spec = &pb.BrokerSpec{
			JournalLimit: Config.Broker.Limit,
			ProcessSpec:  Config.Broker.BuildProcessSpec(srv),
		}
		ks         = broker.NewKeySpace(Config.Etcd.Prefix)
		allocState = allocator.NewObservedState(ks,
			allocator.MemberKey(ks, spec.Id.Zone, spec.Id.Suffix),
			broker.JournalIsConsistent)
		service  = broker.NewService(allocState, lo, etcd)
		rjc      = pb.NewRoutedJournalClient(lo, service)
		tasks    = task.NewGroup(context.Background())
		signalCh = make(chan os.Signal, 1)
	)
	pb.RegisterJournalServer(srv.GRPCServer, service)
	srv.HTTPMux.Handle("/", http_gateway.NewGateway(rjc))
	ks.WatchApplyDelay = Config.Broker.WatchDelay

	log.WithFields(log.Fields{
		"zone":     spec.Id.Zone,
		"id":       spec.Id.Suffix,
		"endpoint": spec.Endpoint,
	}).Info("starting broker")

	mbp.Must(allocator.StartSession(allocator.SessionArgs{
		Etcd:     etcd,
		Tasks:    tasks,
		Spec:     spec,
		State:    allocState,
		LeaseTTL: Config.Etcd.LeaseTTL,
		SignalCh: signalCh,
	}), "failed to start allocator session")

	var persister = fragment.NewPersister(ks)
	broker.SetSharedPersister(persister)

	tasks.Queue("persister.Serve", func() error {
		persister.Serve()
		return nil
	})
	srv.QueueTasks(tasks)
	service.QueueTasks(tasks, srv, persister.Finish)

	// Install signal handler & start broker tasks.
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)
	tasks.GoRun()

	// Block until all tasks complete. Assert none returned an error.
	mbp.Must(tasks.Wait(), "broker task failed")
	log.Info("goodbye")

	return nil
}

func main() {
	var parser = flags.NewParser(Config, flags.Default|flags.AllowBoolValues)

	_, _ = parser.AddCommand("serve", "Serve as Gazette broker", `
Serve a Gazette broker with the provided configuration, until signaled to
exit (via SIGTERM). Upon receiving a signal, the broker will seek to discharge
its responsible journals and will exit only when it can safely do so.
`, &cmdServe{})

	mbp.AddPrintConfigCmd(parser, iniFilename)
	mbp.MustParseConfig(parser, iniFilename)
}
