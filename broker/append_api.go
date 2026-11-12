package broker

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	pb "go.gazette.dev/core/broker/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// Append dispatches the JournalServer.Append API.
func (svc *Service) Append(claims pb.Claims, stream pb.Journal_AppendServer) (err error) {
	var (
		fsm appendFSM
		req *pb.AppendRequest
		pxy *proxyAppendStats
	)
	defer instrumentJournalServerRPC("Append", &err, &fsm.resolved)()

	defer func() {
		if err == nil {
			return
		}
		var addr net.Addr
		if p, ok := peer.FromContext(stream.Context()); ok {
			addr = p.Addr
		}
		var fields = log.Fields{"err": err, "req": req, "client": addr}

		// Attach flow control accounting where this broker actually policed the
		// stream. A proxying broker never reaches stateStreamContent, so it has
		// no stats and they're omitted rather than implying it was the policer.
		if fsm.clientFlowPoliced {
			fields["flow"] = fsm.clientFlowStats
		}
		// Conversely, where we relayed to a primary, report where the relay's
		// time went. The primary polices the relayed stream and blames its
		// "client" -- us -- so this says whether we were in turn starved by our
		// own client or unable to push to the primary.
		if pxy != nil {
			fields["proxy"] = *pxy
		}
		if errors.Cause(err) == ErrFlowControlUnderflow {
			appendFlowUnderflowTotal.WithLabelValues(fsm.clientFlowStats.stalled()).Inc()
		}
		log.WithFields(fields).Warn("served Append RPC failed")
	}()

	if req, err = stream.Recv(); err != nil {
		return err
	} else if err = req.Validate(); err != nil {
		return err
	}

	fsm = appendFSM{
		svc:    svc,
		ctx:    stream.Context(),
		claims: claims,
		req:    *req,
	}
	fsm.run(stream.Recv)

	switch fsm.state {
	case stateProxy:
		req.Header = &fsm.resolved.Header // Attach resolved Header to |req|, which we'll forward.
		pxy = new(proxyAppendStats)
		return proxyAppend(stream, *req, svc.jc, pxy)
	case stateFinished:
		writeHeadGauge.WithLabelValues(fsm.clientFragment.Journal.String()).
			Set(float64(fsm.clientFragment.End))

		return stream.SendAndClose(&pb.AppendResponse{
			Status:        pb.Status_OK,
			Header:        fsm.resolved.Header,
			Commit:        fsm.clientFragment,
			Registers:     &fsm.registers,
			TotalChunks:   fsm.clientTotalChunks,
			DelayedChunks: fsm.clientDelayedChunks,
		})
	case stateError:
		if fsm.resolved.status != pb.Status_OK {
			var resp = &pb.AppendResponse{
				Status: fsm.resolved.status,
				Header: fsm.resolved.Header,
			}
			if fsm.resolved.status == pb.Status_REGISTER_MISMATCH {
				resp.Registers = &fsm.registers
			}
			if fsm.resolved.status == pb.Status_FRAGMENT_STORE_UNHEALTHY {
				resp.StoreHealthError = fsm.err.Error()
			}
			return stream.SendAndClose(resp)
		}
		// Client-initiated RPC cancellations are expected errors.
		if errors.Cause(fsm.err) == context.Canceled {
			return nil
		}
		return fsm.err
	default:
		panic("not reached")
	}
}

// proxyAppendStats accounts for where a proxied Append RPC spent its time.
// The primary polices the relayed stream against MinAppendRate and attributes
// any stall to its "client", which is this broker. These fields say whether we
// were in turn waiting on our own client (RecvMillis) or were unable to push to
// the primary (SendMillis).
type proxyAppendStats struct {
	ContentBytes int64  `json:"content_bytes"`
	Chunks       int64  `json:"chunks"` // Messages relayed, including the opening request.
	OpenMillis   int64  `json:"open_millis"`
	SendMillis   int64  `json:"send_millis"`
	RecvMillis   int64  `json:"recv_millis"`
	RespMillis   int64  `json:"resp_millis"`
	TotalMillis  int64  `json:"total_millis"`
	Stalled      string `json:"stalled"`
}

// String renders stats compactly. The JSON log formatter used in production
// marshals the struct's fields instead; this keeps text-formatted output (tests
// and local runs) from degrading into an unlabeled tuple.
func (s proxyAppendStats) String() string {
	return fmt.Sprintf(
		"stalled=%s bytes=%d chunks=%d open=%dms send=%dms recv=%dms resp=%dms total=%dms",
		s.Stalled, s.ContentBytes, s.Chunks,
		s.OpenMillis, s.SendMillis, s.RecvMillis, s.RespMillis, s.TotalMillis)
}

// proxyAppend forwards an AppendRequest to a resolved peer broker, recording
// into |stats| where its time was spent.
// Pass request by value as we'll later mutate it (via RecvMsg).
func proxyAppend(stream grpc.ServerStream, req pb.AppendRequest, jc pb.JournalClient,
	stats *proxyAppendStats) error {
	// We verified the client's authorization & claims and are running under its context.
	// pb.AuthJournalClient will self-sign claims to proxy this journal on the client's behalf.
	var ctx = pb.WithClaims(stream.Context(), pb.Claims{
		Capability: pb.Capability_APPEND,
		Selector: pb.LabelSelector{
			Include: pb.MustLabelSet("name", req.Journal.String()),
		},
	})
	ctx = pb.WithDispatchRoute(ctx, req.Header.Route, req.Header.ProcessId)

	var nowMillis = func() int64 { return timeNow().UnixNano() / 1e6 }
	var began = nowMillis()

	defer func() {
		stats.TotalMillis = nowMillis() - began

		// Which hop held up the relay? RespMillis is deliberately excluded: it
		// is the primary's commit latency (pipeline sync, peer replication and
		// spool commit) rather than a relay stall, and normally dominates an
		// otherwise healthy append.
		if stats.RecvMillis >= stats.SendMillis {
			stats.Stalled = "client"
		} else {
			stats.Stalled = "primary"
		}
	}()

	var client, err = jc.Append(ctx)
	stats.OpenMillis = nowMillis() - began

	if err != nil {
		return err
	}
	for {
		var sendFrom = nowMillis()
		err = client.SendMsg(&req)
		stats.SendMillis += nowMillis() - sendFrom

		if err != nil {
			break // Client stream is broken. RecvMsg() will return causal error.
		}
		stats.ContentBytes += int64(len(req.Content))
		stats.Chunks++

		var recvFrom = nowMillis()
		err = stream.RecvMsg(&req)
		stats.RecvMillis += nowMillis() - recvFrom

		if err == io.EOF {
			_ = client.CloseSend()
			break
		} else if err != nil {
			_, _ = client.CloseAndRecv() // Drain to free resources.
			return err
		}
	}

	// We don't use CloseAndRecv() here because it returns a confusing
	// EOF error if the stream was broken by the peer (from it's own CloseSend()
	// call under the hood), rather than the actually informative RecvMsg error.
	var resp = new(pb.AppendResponse)
	var respFrom = nowMillis()
	err = client.RecvMsg(resp)
	stats.RespMillis = nowMillis() - respFrom

	if err != nil {
		return err
	} else {
		// Extra RecvMsg to explicitly read EOF, as a work-around for
		// https://github.com/grpc-ecosystem/go-grpc-prometheus/issues/92
		_ = client.RecvMsg(new(pb.AppendResponse))

		return stream.SendMsg(resp)
	}
}
