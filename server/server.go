package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/soheilhy/cmux"
	pb "go.gazette.dev/core/broker/protocol"
	"go.gazette.dev/core/task"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
)

// HTTP/2 flow control windows advertised by the Server and by its connections
// to peers. If both are zero -- the default -- no window options are configured
// and gRPC applies dynamic (BDP-estimated) sizing, growing windows with the
// measured bandwidth-delay product.
//
// Note the two are coupled: configuring EITHER one disables dynamic sizing for
// streams as well as connections, falling back to a 64KB static default for
// whichever is left unset. So "large connection window with a dynamically sized
// stream window" cannot be expressed, and both should be set together.
//
// Static sizing is worth reaching for when connection-level credit is
// oversubscribed: gRPC's dynamic sizing gives the connection the same window as
// an individual stream, so a broker multiplexing MANY journals over one peer
// connection can have a stream that holds stream-level credit yet still cannot
// send, because other streams have filled the connection window. Setting
// InitialConnWindowSize to math.MaxInt32 effectively disables connection-level
// flow control and relies on stream-level flow control alone.
//
// InitialWindowSize then bounds worst-case buffering at
// (concurrent streams * InitialWindowSize) per connection -- but it also caps
// how much a client may have in flight on any one stream, so setting it too low
// throttles bursty writers.
var (
	InitialConnWindowSize int32 = 0
	InitialWindowSize     int32 = 0
)

// flowControlWindows resolves the configured connection and stream windows, or
// (0, 0) to indicate that no options should be configured and gRPC's dynamic
// sizing left in place.
//
// gRPC *ignores* a window below 64KB while still disabling dynamic sizing, so a
// partially-configured pair would silently yield a 64KB window for whichever
// side was left zero -- a 64KB connection window shared by every stream is far
// worse than either intended setting. Configuring either window therefore
// resolves the other to an explicit value rather than leaving it to that trap.
func flowControlWindows() (conn, stream int32) {
	if InitialConnWindowSize == 0 && InitialWindowSize == 0 {
		return 0, 0
	}
	if conn, stream = InitialConnWindowSize, InitialWindowSize; conn == 0 {
		conn = math.MaxInt32 // Effectively disable connection-level flow control.
	}
	if stream == 0 {
		stream = 1 << 16 // gRPC's static default, stated explicitly.
	}
	return conn, stream
}

// flowControlServerOptions returns the window options to configure, which is
// none at all when dynamic sizing is desired.
func flowControlServerOptions() []grpc.ServerOption {
	var conn, stream = flowControlWindows()
	if conn == 0 && stream == 0 {
		return nil
	}
	return []grpc.ServerOption{
		grpc.InitialConnWindowSize(conn),
		grpc.InitialWindowSize(stream),
	}
}

// FlowControlDialOptions returns the window options to configure for a client
// connection, which is none at all when dynamic sizing is desired. It's
// exported so that clients dialing brokers match their configuration.
func FlowControlDialOptions() []grpc.DialOption {
	var conn, stream = flowControlWindows()
	if conn == 0 && stream == 0 {
		return nil
	}
	return []grpc.DialOption{
		grpc.WithInitialConnWindowSize(conn),
		grpc.WithInitialWindowSize(stream),
	}
}

// Server bundles gRPC & HTTP servers, multiplexed over a single bound TCP
// socket (using CMux). Additional protocols may be added to the Server by
// interacting directly with its provided CMux.
type Server struct {
	// Advertised Endpoint of this Server.
	endpoint pb.Endpoint
	// CMux wraps a listener to provide connection protocol multiplexing over
	// a single bound socket. gRPC and HTTP Listeners are provided by default.
	// Additional Listeners may be added directly via CMux.Match() -- though
	// it is then the user's responsibility to Serve the resulting Listeners.
	CMux cmux.CMux
	// GRPCListener is a CMux Listener for gRPC connections.
	GRPCListener net.Listener
	// HTTPListener is a CMux Listener for HTTP connections.
	HTTPListener net.Listener
	// HTTPMux is the http.ServeMux which is served by Serve().
	HTTPMux *http.ServeMux
	// GRPCServer is the gRPC server mux which is served by Serve().
	GRPCServer *grpc.Server
	// GRPCLoopback is a dialed connection to this GRPCServer.
	GRPCLoopback *grpc.ClientConn

	httpServer http.Server
}

// New builds and returns a Server of the given TCP network interface `iface`
// and `port` for serving traffic directed at `host`.
// `port` may be empty, in which case a random free port is assigned.
// if `tlsConfig` is non-nil, the Server uses TLS (and is otherwise in the clear).
func New(
	iface, host, port string,
	serverTLS, peerTLS *tls.Config,
	maxGRPCRecvSize uint32,
	wrapListener func(net.Listener, *tls.Config) (net.Listener, error),
) (*Server, error) {
	var network, bind string
	if port == "" {
		network, bind = "tcp", fmt.Sprintf("%s:0", iface) // Assign a random free port.
	} else if u, err := url.Parse(port); err == nil && u.Scheme == "unix" {
		network, bind = "unix", u.Path

		// Ignore TLS for UDS. It's already local, and clients cannot use the
		// advertised endpoint scheme to determine whether to expect TLS.
		serverTLS, peerTLS = nil, nil
	} else {
		network, bind = "tcp", fmt.Sprintf("%s:%s", iface, port)
	}

	var listener, err = net.Listen(network, bind)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to bind service address (%s)", bind)
	}

	// If no host was specified, use the hostname.
	if host == "" {
		if host, err = os.Hostname(); err != nil {
			return nil, err
		}
	}
	// If no port was specified, query the dynamic port which we bound.
	if port == "" {
		port = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	}

	var endpoint string
	if network == "unix" {
		endpoint = fmt.Sprintf("unix://%s%s", host, bind)
	} else {
		endpoint = fmt.Sprintf("://%s:%s", host, port)

		if serverTLS != nil {
			endpoint = "https" + endpoint
		} else {
			endpoint = "http" + endpoint
		}
	}

	var srv = &Server{
		endpoint: pb.Endpoint(endpoint),
		HTTPMux:  http.NewServeMux(),
		// The window a receiver advertises bounds what its senders may push, so
		// flow control options here govern all inbound traffic -- notably
		// Appends relayed to us by a peer acting as proxy.
		GRPCServer: grpc.NewServer(append([]grpc.ServerOption{
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
			grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
			grpc.MaxRecvMsgSize(int(maxGRPCRecvSize)),
		}, flowControlServerOptions()...)...),
	}

	// gRPC v1.67+ requires that we advertise "h2" via ALPN.
	// However we only offer HTTP/2 for gRPC connections,
	// so pick it only if "http/1.1" isn't offered
	// (which is true only of gRPC clients).
	if serverTLS != nil {
		serverTLS.NextProtos = []string{"http/1.1", "h2"}
	}

	if wrapListener != nil {
		if listener, err = wrapListener(listener, serverTLS); err != nil {
			return nil, fmt.Errorf("failed to wrap listener: %w", err)
		}
	} else if serverTLS != nil {
		listener = tls.NewListener(listener, serverTLS)
	}
	srv.CMux = cmux.New(listener)

	srv.CMux.HandleError(func(err error) bool {
		if _, ok := err.(net.Error); !ok {
			log.WithField("err", err).Warn("failed to CMux client connection to a listener")
		}
		return true // Continue serving RawListener.
	})
	// CMux ReadTimeout controls how long we'll wait for an opening send from
	// the client which allows CMux to sniff a matching listening mux. It has
	// no effect once the connection has been matched to a mux.
	// See: https://github.com/soheilhy/cmux/issues/76
	srv.CMux.SetReadTimeout(GracefulStopTimeout / 2)

	// GRPCListener sniffs for HTTP/2 in-the-clear connections which have
	// "Content-Type: application/grpc". Note this matcher will send an initial
	// empty SETTINGS frame to the client, as gRPC clients delay the first
	// request until the HTTP/2 handshake has completed.
	srv.GRPCListener = srv.CMux.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"))

	// This grpc.ClientConn connects to this server's loopback, and also
	// to peer server addresses via the dispatch balancer. It has particular
	// knowledge of what addresses *should* be reach-able (from Etcd
	// advertisements). Use an aggressive back-off for server-to-server
	// connections, as it's crucial for quick cluster recovery from
	// partitions, etc.
	var backoffConfig = backoff.DefaultConfig
	backoffConfig.MaxDelay = time.Millisecond * 500

	// This ClientConn is the origin of every broker-to-peer connection (its
	// balancer dials peers directly), so flow control options here bound what we
	// may push to a peer as well as what a peer may push to us.
	srv.GRPCLoopback, err = grpc.DialContext(
		context.Background(),
		srv.endpoint.GRPCAddr(),
		append([]grpc.DialOption{
			grpc.WithTransportCredentials(pb.NewDispatchedCredentials(peerTLS, srv.endpoint)),
			grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoffConfig}),
			grpc.WithDefaultServiceConfig(fmt.Sprintf(`{"loadBalancingConfig": [{"%s":{}}]}`, pb.DispatcherGRPCBalancerName)),
			// Instrument client for gRPC metric collection.
			grpc.WithUnaryInterceptor(grpc_prometheus.UnaryClientInterceptor),
			grpc.WithStreamInterceptor(grpc_prometheus.StreamClientInterceptor),
		}, FlowControlDialOptions()...)...,
	)

	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial gRPC loopback")
	}

	// Connections sending HTTP/1 verbs (GET, PUT, POST etc) are assumed to be HTTP.
	srv.HTTPListener = srv.CMux.Match(cmux.HTTP1Fast())

	return srv, nil
}

func BuildTLSConfig(certPath, keyPath, trustedCAPath string) (*tls.Config, error) {
	var tlsConfig = &tls.Config{
		ClientAuth: tls.NoClientCert,
	}

	// Load a presented certificate and key.
	if certPath != "" {
		var cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate and key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load a trusted Certificate Authority, which is required for clients.
	if trustedCAPath != "" {
		caCert, err := os.ReadFile(trustedCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		var caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}
		tlsConfig.ClientCAs = caCertPool
		tlsConfig.RootCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

// MustLoopback builds and returns a new Server instance bound to a random
// port on the loopback interface. It panics on error.
func MustLoopback() *Server {
	if srv, err := New("127.0.0.1", "127.0.0.1", "", nil, nil, 1<<20, nil); err != nil {
		log.WithField("err", err).Panic("failed to build Server")
		panic("not reached")
	} else {
		return srv
	}
}

// Endpoint of the Server.
func (s *Server) Endpoint() pb.Endpoint {
	return s.endpoint
}

// QueueTasks serving the CMux, HTTP, and gRPC component servers onto the task.Group.
// If additional Listeners are derived from the Server.CMux, attempts to Accept
// will block until the CMux itself begins serving.
func (s *Server) QueueTasks(tg *task.Group) {
	tg.Queue("server.ServeCMux", func() error {
		if err := s.CMux.Serve(); err != nil && tg.Context().Err() == nil {
			return err
		}
		return nil // Swallow error on cancellation.
	})
	tg.Queue("server.ServeHTTP", func() error {
		// Disable Close() of the HTTPListener, because http.Server Shutdown()
		// is invoked after grpc.Server GracefulStop(), which has already closed
		// the underlying listener.
		var ln = noopCloser{s.HTTPListener}

		s.httpServer.Handler = s.HTTPMux
		if err := s.httpServer.Serve(ln); err != nil && tg.Context().Err() == nil {
			return err
		}
		return nil // Swallow error on cancellation.
	})
	tg.Queue("server.ServeGRPC", func() error {
		if err := s.GRPCServer.Serve(s.GRPCListener); err != grpc.ErrServerStopped {
			return err
		}
		return nil
	})
}

// BoundedGracefulStop attempts to perform a graceful stop of the server,
// but falls back to a hard stop if the graceful stop doesn't complete
// reasonably quickly.
func (s *Server) BoundedGracefulStop() {
	var ctx, cancel = context.WithCancel(context.Background())
	var timer = time.AfterFunc(GracefulStopTimeout, func() {
		log.Error("grpc.GracefulStop took too long, issuing a hard Stop")

		// Close loopback even though the server isn't stopped, to unblock any
		// requests which may be wedged sending to an unresponsive peer.
		_ = s.GRPCLoopback.Close()

		s.GRPCServer.Stop()
		cancel()
	})
	// GracefulStop immediately closes the underlying RawListener.
	s.GRPCServer.GracefulStop()

	// Shutdown causes httpServer.Serve to return immediately.
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.WithField("err", err).Error("http.Server Shutdown finished with error")
	}
	timer.Stop()
}

type noopCloser struct {
	net.Listener
}

func (noopCloser) Close() error { return nil }

// GracefulStopTimeout is the amount of time BoundedGracefulStop will wait
// before performing a hard server Stop.
var GracefulStopTimeout = 15 * time.Second
