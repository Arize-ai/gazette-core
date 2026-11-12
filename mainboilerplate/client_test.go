package mainboilerplate

import (
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.gazette.dev/core/server"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestClientFlowControlOptionsAreUnconditional pins the property which makes
// the client windows correct: they do not vary with the broker's `server` vars.
// Those are assigned by `gazette serve` alone, so deriving client windows from
// them yields no windows at all in a gazctl or consumer process -- and gRPC's
// dynamic sizing then gives the connection the same window as a single stream,
// so many journals multiplexed onto one connection block on each other.
func TestClientFlowControlOptionsAreUnconditional(t *testing.T) {
	defer func(conn, stream int32) {
		server.InitialConnWindowSize, server.InitialWindowSize = conn, stream
	}(server.InitialConnWindowSize, server.InitialWindowSize)

	for _, tc := range []struct {
		conn, stream int32
		description  string
	}{
		{0, 0, "brokers left at the dynamic-sizing default"},
		{math.MaxInt32, 1 << 18, "brokers configured with static windows"},
	} {
		server.InitialConnWindowSize, server.InitialWindowSize = tc.conn, tc.stream

		require.Len(t, clientFlowControlOptions(), 2, tc.description)
	}
}

// TestClientAdvertisedFlowControlWindows asserts what clientFlowControlOptions
// actually puts on the wire. It's verified here rather than trusted because the
// two gRPC options are coupled in a non-obvious way: configuring either one
// disables dynamic (BDP) sizing for *both*, silently pinning whichever is left
// unset to a 64KB static window.
func TestClientAdvertisedFlowControlWindows(t *testing.T) {
	var listener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// gRPC dials lazily, so ask it to connect and then read what it sends.
	// Both the SETTINGS and the connection WINDOW_UPDATE are written during
	// transport setup, before the client reads anything back from us, so we
	// never have to play the part of a server.
	var cc *grpc.ClientConn
	cc, err = grpc.NewClient("passthrough:///"+listener.Addr().String(),
		append(clientFlowControlOptions(),
			grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	require.NoError(t, err)
	defer cc.Close()
	cc.Connect()

	var conn net.Conn
	conn, err = listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	var preface = make([]byte, len(http2.ClientPreface))
	_, err = io.ReadFull(conn, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface))

	var streamWindow, connIncrement uint32
	var framer = http2.NewFramer(conn, conn)

	for streamWindow == 0 || connIncrement == 0 {
		var frame, err = framer.ReadFrame()
		require.NoError(t, err)

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

	// Asserted as literals, not against the constants, so that changing a
	// client window is a deliberate edit here rather than a silent one. These
	// are the values clients have always used: an effectively unlimited
	// connection window, and gRPC's 64KB stream window now stated outright.
	require.Equal(t, uint32(1<<16), streamWindow,
		"client must advertise an explicit SETTINGS_INITIAL_WINDOW_SIZE")
	// The connection window opens at the protocol default of 65535, which the
	// client extends to math.MaxInt32 with this increment.
	require.Equal(t, uint32(math.MaxInt32-65535), connIncrement,
		"client must extend the stream-zero connection window")
}
