package server

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pb "go.gazette.dev/core/broker/protocol"
	"go.gazette.dev/core/task"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestAdvertisedFlowControlWindows asserts the HTTP/2 flow control windows which
// the Server actually advertises to its clients and peers. This is verified on
// the wire because the relevant gRPC options are coupled in a non-obvious way:
// configuring either window disables gRPC's dynamic (BDP) window sizing for
// *both*, silently falling back to a 64KB static stream window if the stream
// window is left unset. Both directions matter: an under-sized connection
// window starves proxied Appends, while an under-sized stream window caps what
// a bursty writer may have in flight.
func TestAdvertisedFlowControlWindows(t *testing.T) {
	defer func(conn, stream int32) {
		InitialConnWindowSize, InitialWindowSize = conn, stream
	}(InitialConnWindowSize, InitialWindowSize)

	InitialConnWindowSize, InitialWindowSize = math.MaxInt32, 1<<18

	var streamWindow, connIncrement = probeAdvertisedWindows(t)

	require.Equal(t, uint32(InitialWindowSize), streamWindow,
		"server must advertise an explicit SETTINGS_INITIAL_WINDOW_SIZE")
	// The connection window opens at the protocol default of 65535, which the
	// server extends to InitialConnWindowSize with this increment.
	require.Equal(t, uint32(InitialConnWindowSize-65535), connIncrement,
		"server must extend the stream-zero connection window")
}

// TestDynamicFlowControlWindows asserts that the zero default configures no
// windows at all, which is the only way to leave gRPC's dynamic (BDP) sizing in
// effect -- and is therefore not observable except by its silence on the wire.
func TestDynamicFlowControlWindows(t *testing.T) {
	defer func(conn, stream int32) {
		InitialConnWindowSize, InitialWindowSize = conn, stream
	}(InitialConnWindowSize, InitialWindowSize)

	InitialConnWindowSize, InitialWindowSize = 0, 0

	var streamWindow, connIncrement = probeAdvertisedWindows(t)

	require.Zero(t, streamWindow,
		"server must not advertise SETTINGS_INITIAL_WINDOW_SIZE when sizing is dynamic")
	require.Zero(t, connIncrement,
		"server must not extend the connection window when sizing is dynamic")
}

// probeAdvertisedWindows starts a Server and speaks raw HTTP/2 to it, returning
// the stream window it advertises via SETTINGS and the increment by which it
// extends the connection window. Either is zero if never sent.
func probeAdvertisedWindows(t *testing.T) (streamWindow, connIncrement uint32) {
	pb.RegisterGRPCDispatcher("local")

	var srv = MustLoopback()
	var tg = task.NewGroup(context.Background())
	srv.QueueTasks(tg)
	tg.GoRun()

	defer func() {
		tg.Cancel() // Serve errors of a cancelled Group are swallowed.
		srv.BoundedGracefulStop()
		require.NoError(t, tg.Wait())
	}()

	var conn, err = net.Dial("tcp", srv.Endpoint().GRPCAddr())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = conn.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)

	var framer = http2.NewFramer(conn, conn)
	require.NoError(t, framer.WriteSettings())

	// CMux routes to the gRPC listener only after sniffing a gRPC content-type,
	// so open a stream which presents one.
	var hdr []byte
	var enc = hpack.NewEncoder((*sliceWriter)(&hdr))
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/probe/Probe"},
		{Name: ":authority", Value: "localhost"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		require.NoError(t, enc.WriteField(f))
	}
	require.NoError(t, framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hdr,
		EndHeaders:    true,
	}))

	// Collect the server's advertised windows, reading until it ACKs our
	// SETTINGS. gRPC writes its own SETTINGS and any connection-level
	// WINDOW_UPDATE before it reads ours, so the ACK is a reliable terminator --
	// and makes the *absence* of those frames observable immediately, rather
	// than by waiting out the deadline. (CMux's matcher also sends an empty
	// SETTINGS frame of its own ahead of gRPC's, which carries no windows.)
	for {
		var frame, err = framer.ReadFrame()
		if err != nil {
			break
		}
		if f, ok := frame.(*http2.SettingsFrame); ok && f.IsAck() {
			break
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				streamWindow = v
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				connIncrement = f.Increment
			}
		}
	}

	return streamWindow, connIncrement
}

// sliceWriter adapts a byte slice to the io.Writer expected by hpack.
type sliceWriter []byte

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}

// TestFlowControlWindowResolution covers the partially-configured cases, which
// the on-the-wire tests above cannot distinguish: gRPC ignores a sub-64KB
// window value but still disables dynamic sizing, so "configured as zero" and
// "not configured" look identical on the wire while behaving very differently.
func TestFlowControlWindowResolution(t *testing.T) {
	defer func(conn, stream int32) {
		InitialConnWindowSize, InitialWindowSize = conn, stream
	}(InitialConnWindowSize, InitialWindowSize)

	for _, tc := range []struct {
		conn, stream          int32
		expectConn, expectStr int32
		description           string
	}{
		{0, 0, 0, 0, "unset leaves dynamic sizing in place"},
		{math.MaxInt32, 1 << 18, math.MaxInt32, 1 << 18, "both set are used as given"},
		{0, 1 << 18, math.MaxInt32, 1 << 18, "stream alone implies an open connection window"},
		{math.MaxInt32, 0, math.MaxInt32, 1 << 16, "connection alone implies an explicit stream window"},
	} {
		InitialConnWindowSize, InitialWindowSize = tc.conn, tc.stream

		var conn, stream = flowControlWindows()
		require.Equal(t, tc.expectConn, conn, tc.description)
		require.Equal(t, tc.expectStr, stream, tc.description)

		// Options are configured in every case but the fully-unset one.
		require.Equal(t, tc.expectConn == 0 && tc.expectStr == 0,
			flowControlServerOptions() == nil, tc.description)
		require.Equal(t, tc.expectConn == 0 && tc.expectStr == 0,
			FlowControlDialOptions() == nil, tc.description)
	}
}
