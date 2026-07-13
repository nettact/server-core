// This file isolates the coder/websocket dependency of the session machinery.
// hub.serve and session work against wire.Conn; wsConn adapts a server-accepted
// WebSocket to that interface (owning the codec fixed by the negotiated
// subprotocol and translating close codes both ways). The in-process pipe used
// by DialLocal implements the same wire.Conn without touching this file.
package agentws

import (
	"context"
	"errors"
	"fmt"

	"github.com/coder/websocket"

	"github.com/nettact/protocol/wire"
)

// errBadFrame marks an inbound frame the codec could not decode. Only the
// WebSocket transport can produce it (the in-memory pipe passes decoded frames);
// the read loop maps it to a CloseProtocolError so a malformed agent is told its
// frame was rejected rather than seeing a generic close.
var errBadFrame = errors.New("agentws: malformed frame")

// wsConn adapts a server-side *websocket.Conn to wire.Conn. contentType is
// fixed by the subprotocol negotiated at upgrade time.
type wsConn struct {
	c           *websocket.Conn
	contentType string
}

func (w *wsConn) ReadFrame(ctx context.Context) (wire.Frame, error) {
	_, data, err := w.c.Read(ctx)
	if err != nil {
		if code := websocket.CloseStatus(err); code != -1 {
			return wire.Frame{}, &wire.CloseError{Code: wire.CloseCode(code), Reason: err.Error()}
		}
		return wire.Frame{}, err
	}
	f, err := wire.UnmarshalFrame(data, w.contentType)
	if err != nil {
		return wire.Frame{}, fmt.Errorf("%w: %v", errBadFrame, err)
	}
	return f, nil
}

func (w *wsConn) WriteFrame(ctx context.Context, f wire.Frame) error {
	// Marshal happens here (previously in writeLoop). A server-built frame always
	// carries exactly one payload, so a marshal error is a programming bug the
	// caller surfaces by tearing the session down.
	data, err := wire.MarshalFrame(f, w.contentType)
	if err != nil {
		return err
	}
	msgType := websocket.MessageBinary
	if w.contentType == wire.ContentTypeJSON {
		msgType = websocket.MessageText
	}
	return w.c.Write(ctx, msgType, data)
}

func (w *wsConn) Ping(ctx context.Context) error {
	return w.c.Ping(ctx)
}

func (w *wsConn) Close(code wire.CloseCode, reason string) error {
	return w.c.Close(websocket.StatusCode(code), reason)
}
