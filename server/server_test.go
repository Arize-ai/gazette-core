package server

import (
	"context"
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
// window is left unset. An under-sized connection window starves proxied
// Appends, which the primary polices against MinAppendRate.
func TestAdvertisedFlowControlWindows(t *testing.T) {
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

	// Collect the server's advertised windows. Note CMux's matcher sends its own
	// empty SETTINGS frame ahead of the gRPC server's, so read until both the
	// stream window (SETTINGS) and connection window (stream-zero WINDOW_UPDATE)
	// have been observed.
	// A server which advertises neither window sends neither frame, so bound the
	// read on the connection deadline rather than blocking indefinitely.
	var streamWindow, connIncrement uint32

	for streamWindow == 0 || connIncrement == 0 {
		var frame, err = framer.ReadFrame()
		if err != nil {
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

	require.Equal(t, uint32(InitialWindowSize), streamWindow,
		"server must advertise an explicit SETTINGS_INITIAL_WINDOW_SIZE")
	// The connection window opens at the protocol default of 65535, which the
	// server extends to InitialConnWindowSize with this increment.
	require.Equal(t, uint32(InitialConnWindowSize-65535), connIncrement,
		"server must extend the stream-zero connection window")
}

// sliceWriter adapts a byte slice to the io.Writer expected by hpack.
type sliceWriter []byte

func (w *sliceWriter) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}
