// DNS server implementation for DNS-over-QUIC (RFC9250)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package doq

import (
    "context"
    "crypto/tls"
    "encoding/binary"
    "errors"
    "io"
    "net"
    // "strings"
    "sync"
    "syscall"
    "time"

    "golang.org/x/sys/unix"

    "github.com/miekg/dns"

    "github.com/lucas-clemente/quic-go"
    // For enabling QUIC connection tracing:
    // "github.com/lucas-clemente/quic-go/logging"
    // "github.com/lucas-clemente/quic-go/qlog"
    // "os"
)

// aLongTimeAgo is a non-zero time, far in the past, used for
// immediate cancelation of network operations.
var aLongTimeAgo = time.Unix(1, 0)

type connection struct {
    lock    sync.RWMutex
    conn    quic.Connection
    streams map[quic.Stream]struct{}
    wg      sync.WaitGroup
}

type response struct {
    closed         bool // connection has been closed
    hijacked       bool // connection has been hijacked by handler
    tsigTimersOnly bool
    tsigStatus     error
    // TODO:
    // tsigRequestMAC string
    // tsigProvider   dns.TsigProvider
    doq        quic.Stream // i/o connection if QUIC was used
    writer     dns.Writer  // writer to output the raw DNS bits
    localAddr  net.Addr
    remoteAddr net.Addr
}

// Reader reads raw DNS messages; each call to ReadQUIC should return an entire message.
type Reader interface {
    // ReadQUIC reads a raw message from a QUIC stream. Implementations may alter
    // connection properties, for example the read-deadline.
    ReadQUIC(stream quic.Stream, timeout time.Duration) ([]byte, error)
}

// DecorateReader is a decorator hook for extending or supplanting the functionality of a Reader.
// Implementations should never return a nil Reader.
type DecorateReader func(Reader) Reader

// A Server defines parameters for running an DNS server.
type Server struct {
    // Address to listen on, ":853" if empty.
    Addr string
    // Set to "doq" for DNS-over-QUIC (RFC9250)
    Net string
    // QUIC Listener to use, this is to aid in systemd's socket activation.
    Listener quic.Listener
    // TLS connection configuration
    TLSConfig *tls.Config
    // Handler to invoke, dns.DefaultServeMux if nil.
    Handler dns.Handler
    // The net.Conn.SetReadTimeout value for new connections, defaults to 2 * time.Second.
    ReadTimeout time.Duration
    // The net.Conn.SetWriteTimeout value for new connections, defaults to 2 * time.Second.
    WriteTimeout time.Duration
    // TCP idle timeout for multiple queries, if nil, defaults to 8 * time.Second (RFC 5966).
    IdleTimeout func() time.Duration
    // TODO:
    // // An implementation of the dns.TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
    // TsigProvider dns.TsigProvider
    // // Secret(s) for Tsig map[<zonename>]<base64 secret>. The zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2).
    // TsigSecret map[string]string
    // If NotifyStartedFunc is set it is called once the server has started listening.
    NotifyStartedFunc func()
    // DecorateReader is optional, allows customization of the process that reads raw DNS messages.
    DecorateReader DecorateReader
    // DecorateWriter is optional, allows customization of the process that writes raw DNS messages.
    DecorateWriter dns.DecorateWriter
    // Whether to set the SO_REUSEPORT socket option, allowing multiple listeners to be bound to a single address.
    // It is only supported on go1.11+ and when using ListenAndServe.
    ReusePort bool
    // AcceptMsgFunc will check the incoming message and will reject it early in the process.
    // By default DefaultMsgAcceptFunc will be used.
    MsgAcceptFunc dns.MsgAcceptFunc

    // Shutdown handling
    lock     sync.RWMutex
    started  bool
    shutdown chan struct{}
    conns    map[*connection]struct{}
}

// TODO:
// func (srv *Server) tsigProvider() dns.TsigProvider {
//     if srv.TsigProvider != nil {
//         return srv.TsigProvider
//     }
//     if srv.TsigSecret != nil {
//         return tsigSecretProvider(srv.TsigSecret)
//     }
//     return nil
// }

func (srv *Server) init() {
    srv.shutdown = make(chan struct{})
    srv.conns = make(map[*connection]struct{})

    srv.Net = "doq"
    if srv.MsgAcceptFunc == nil {
        srv.MsgAcceptFunc = dns.DefaultMsgAcceptFunc
    }
    if srv.Handler == nil {
        srv.Handler = dns.DefaultServeMux
    }
    if srv.ReadTimeout == 0 {
        srv.ReadTimeout = time.Second * 2
    }
    if srv.WriteTimeout == 0 {
        srv.WriteTimeout = time.Second * 2
    }
}

func unlockOnce(l sync.Locker) func() {
    var once sync.Once
    return func() { once.Do(l.Unlock) }
}

// ListenAndServe starts a nameserver on the configured address in *Server.
func (srv *Server) ListenAndServe() error {
    unlock := unlockOnce(&srv.lock)
    srv.lock.Lock()
    defer unlock()

    if srv.started {
        return errors.New("doq: server already started")
    }

    addr := srv.Addr
    if addr == "" {
        addr = ":853"
    }

    srv.init()

    if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
        return errors.New("doq: neither Certificates nor GetCertificate set in Config")
    }
    srv.TLSConfig.NextProtos = []string{"doq", "doq-i03"}

    var lc net.ListenConfig
    if srv.ReusePort {
        lc.Control = func(network, address string, c syscall.RawConn) error {
            var opErr error
            err := c.Control(func(fd uintptr) {
                opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
            })
            if err != nil {
                return err
            }

            return opErr
        }
    }

    l, err := lc.ListenPacket(context.Background(), "udp", addr)
    if err != nil {
        return err
    }
    // TODO: Why is this used?
    // u := l.(*net.UDPConn)
    // if e := setUDPSocketOptions(u); e != nil {
    //     u.Close()
    //     return e
    // }
    ql, err := quic.Listen(l, srv.TLSConfig, nil)
    // For enabling QUIC connection tracing:
    // &quic.Config{
    //     Tracer: qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
    //         return io.WriteCloser(os.Stdout)
    //     }),
    // })
    if err != nil {
        l.Close()
        return err
    }
    srv.Listener = ql
    srv.started = true
    unlock()
    return srv.serveQUIC(ql)
}

// ActivateAndServe starts a nameserver with the PacketConn or Listener
// configured in *Server. Its main use is to start a server from systemd.
func (srv *Server) ActivateAndServe() error {
    // unlock := unlockOnce(&srv.lock)
    // srv.lock.Lock()
    // defer unlock()
    //
    // if srv.started {
    //     return &Error{err: "server already started"}
    // }
    //
    // srv.init()
    //
    // if srv.PacketConn != nil {
    //     // Check PacketConn interface's type is valid and value
    //     // is not nil
    //     if t, ok := srv.PacketConn.(*net.UDPConn); ok && t != nil {
    //         if e := setUDPSocketOptions(t); e != nil {
    //             return e
    //         }
    //     }
    //     srv.started = true
    //     unlock()
    //     return srv.serveUDP(srv.PacketConn)
    // }
    // if srv.Listener != nil {
    //     srv.started = true
    //     unlock()
    //     return srv.serveTCP(srv.Listener)
    // }
    // return &Error{err: "bad listeners"}

    return errors.New("TODO")
}

// Shutdown shuts down a server. After a call to Shutdown, ListenAndServe and
// ActivateAndServe will return.
func (srv *Server) Shutdown() error {
    return srv.ShutdownContext(context.Background())
}

// ShutdownContext shuts down a server. After a call to ShutdownContext,
// ListenAndServe and ActivateAndServe will return.
//
// A context.Context may be passed to limit how long to wait for connections
// to terminate.
func (srv *Server) ShutdownContext(ctx context.Context) error {
    srv.lock.Lock()
    if !srv.started {
        srv.lock.Unlock()
        return errors.New("doq: server not started")
    }

    srv.started = false

    if srv.Listener != nil {
        srv.Listener.Close()
    }

    for rw := range srv.conns {
        // rw.SetReadDeadline(aLongTimeAgo) // Unblock reads
        // Close QUIC connections because above deadline only affects streams within the connection
        rw.conn.CloseWithError(0, "")
    }

    srv.lock.Unlock()

    var ctxErr error
    select {
    case <-srv.shutdown:
    case <-ctx.Done():
        ctxErr = ctx.Err()
    }

    return ctxErr
}

func (srv *Server) serveDNS(m []byte, w *response) {
    if len(m) < 12 {
        // Let client hang, they are sending crap; any reply can be used to amplify.
        return
    }

    var dh dns.Header
    dh.Id = binary.BigEndian.Uint16(m[0:])
    dh.Bits = binary.BigEndian.Uint16(m[2:])
    dh.Qdcount = binary.BigEndian.Uint16(m[4:])
    dh.Ancount = binary.BigEndian.Uint16(m[6:])
    dh.Nscount = binary.BigEndian.Uint16(m[8:])
    dh.Arcount = binary.BigEndian.Uint16(m[10:])

    req := new(dns.Msg)

    switch action := srv.MsgAcceptFunc(dh); action {
    case dns.MsgAccept:
        if req.Unpack(m) == nil {
            break
        }

        fallthrough
    case dns.MsgReject, dns.MsgRejectNotImplemented:
        // try unpacking just header if it wasn't done or if Unpack() above failed
        req.Unpack(m[:12])
        opcode := req.Opcode
        req.SetRcodeFormatError(req)
        req.Zero = false
        if action == dns.MsgRejectNotImplemented {
            req.Opcode = opcode
            req.Rcode = dns.RcodeNotImplemented
        }

        // Are we allowed to delete any OPT records here?
        req.Ns, req.Answer, req.Extra = nil, nil, nil

        w.WriteMsg(req)
        fallthrough
    case dns.MsgIgnore:
        return
    }

    // TODO:
    // w.tsigStatus = nil
    // if w.tsigProvider != nil {
    //     if t := req.IsTsig(); t != nil {
    //         w.tsigStatus = tsigVerifyProvider(m, w.tsigProvider, "", false)
    //         w.tsigTimersOnly = false
    //         w.tsigRequestMAC = t.MAC
    //     }
    // }

    srv.Handler.ServeDNS(w, req) // Writes back to the client
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m *dns.Msg) (err error) {
    if w.closed {
        return errors.New("doq: WriteMsg called after Close")
    }

    var data []byte
    // TODO:
    // if w.tsigProvider != nil { // if no provider, dont check for the tsig (which is a longer check)
    //     if t := m.IsTsig(); t != nil {
    //         data, w.tsigRequestMAC, err = tsigGenerateProvider(m, w.tsigProvider, w.tsigRequestMAC, w.tsigTimersOnly)
    //         if err != nil {
    //             return err
    //         }
    //         _, err = w.writer.Write(data)
    //         return err
    //     }
    // }
    data, err = m.Pack()
    if err != nil {
        return err
    }
    _, err = w.writer.Write(data)
    return err
}

// Write implements the ResponseWriter.Write method.
func (w *response) Write(m []byte) (int, error) {
    if w.closed {
        return 0, errors.New("doq: Write called after Close")
    }

    if len(m) > dns.MaxMsgSize {
        return 0, errors.New("doq: message too large")
    }

    msg := make([]byte, 2+len(m))
    binary.BigEndian.PutUint16(msg, uint16(len(m)))
    copy(msg[2:], m)
    return w.doq.Write(msg)
}

// LocalAddr implements the ResponseWriter.LocalAddr method.
func (w *response) LocalAddr() net.Addr { return w.localAddr }

// RemoteAddr implements the ResponseWriter.RemoteAddr method.
func (w *response) RemoteAddr() net.Addr { return w.remoteAddr }

// TsigStatus implements the ResponseWriter.TsigStatus method.
func (w *response) TsigStatus() error { return w.tsigStatus }

// TsigTimersOnly implements the ResponseWriter.TsigTimersOnly method.
func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

// Hijack implements the ResponseWriter.Hijack method.
func (w *response) Hijack() { w.hijacked = true }

// Close implements the ResponseWriter.Close method
func (w *response) Close() error {
    if w.closed {
        return errors.New("doq: stream already closed")
    }
    w.closed = true

    return w.doq.Close()
}

// ConnectionState() implements the ConnectionStater.ConnectionState() interface.
func (w *response) ConnectionState() *tls.ConnectionState {
    // TODO:
    // type tlsConnectionStater interface {
    //     ConnectionState() tls.ConnectionState
    // }
    // if v, ok := w.tcp.(tlsConnectionStater); ok {
    //     t := v.ConnectionState()
    //     return &t
    // }
    return nil
}

// func (c *quicConn) Read(b []byte) (int, error) {
//     panic("not supported")
// }
// func (c *quicConn) Write(b []byte) (int, error) {
//     panic("not supported")
// }
// func (c *quicConn) Close() error {
//     return c.conn.CloseWithError(0, "")
// }
// func (c *quicConn) LocalAddr() net.Addr {
//     return c.conn.LocalAddr()
// }
// func (c *quicConn) RemoteAddr() net.Addr {
//     return c.conn.RemoteAddr()
// }
// func (c *quicConn) SetDeadline(t time.Time) error {
//     c.lock.Lock()
//     for s := range c.streams {
//         s.SetDeadline(t)
//     }
//     c.lock.Unlock()
//     return nil
// }
// func (c *quicConn) SetReadDeadline(t time.Time) error {
//     c.lock.Lock()
//     for s := range c.streams {
//         s.SetReadDeadline(t)
//     }
//     c.lock.Unlock()
//     return nil
// }
// func (c *quicConn) SetWriteDeadline(t time.Time) error {
//     c.lock.Lock()
//     for s := range c.streams {
//         s.SetWriteDeadline(t)
//     }
//     c.lock.Unlock()
//     return nil
// }

// serveQUIC
func (srv *Server) serveQUIC(l quic.Listener) error {
    defer l.Close()

    if srv.NotifyStartedFunc != nil {
        srv.NotifyStartedFunc()
    }

    var wg sync.WaitGroup
    defer func() {
        wg.Wait()
        close(srv.shutdown)
    }()

    for {
        conn, err := l.Accept(context.Background())
        srv.lock.Lock()
        if err != nil {
            // TODO: Use?
            // if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
            //     continue
            // }
            srv.lock.Unlock()
            return err
        }
        if !srv.started {
            srv.lock.Unlock()
            return nil
        }
        // Track the connection to allow unblocking reads on shutdown.
        c := &connection{conn: conn, streams: make(map[quic.Stream]struct{})}
        srv.conns[c] = struct{}{}
        srv.lock.Unlock()
        wg.Add(1)
        go srv.serveQUICConn(&wg, c)
    }
    return nil
}

// Serve a new QUIC connection.
func (srv *Server) serveQUICConn(wg *sync.WaitGroup, c *connection) {
    for {
        stream, err := c.conn.AcceptStream(context.Background())
        if err != nil {
            // TODO: What to do with err here? Close conn?
            break
        }
        c.lock.Lock()
        // Track the stream to allow unblocking reads on shutdown.
        c.streams[stream] = struct{}{}
        c.lock.Unlock()
        c.wg.Add(1)
        go srv.serveQUICStream(c, stream)
    }

    c.wg.Wait()

    srv.lock.Lock()
    delete(srv.conns, c)
    srv.lock.Unlock()

    wg.Done()
}

type streamReader struct {
    *Server
}

// Serve a new QUIC stream.
func (srv *Server) serveQUICStream(c *connection, stream quic.Stream) {
    defer func() {
        c.lock.Lock()
        delete(c.streams, stream)
        c.lock.Unlock()
        c.wg.Done()
    }()

    w := &response{
        // tsigProvider: srv.tsigProvider(),
        doq:        stream,
        localAddr:  c.conn.LocalAddr(),
        remoteAddr: c.conn.RemoteAddr(),
    }
    if srv.DecorateWriter != nil {
        w.writer = srv.DecorateWriter(w)
    } else {
        w.writer = w
    }

    reader := Reader(streamReader{srv})
    if srv.DecorateReader != nil {
        reader = srv.DecorateReader(reader)
    }

    m, err := reader.ReadQUIC(stream, srv.ReadTimeout)
    if err != nil {
        // TODO: what to do here?
        return
    }
    srv.serveDNS(m, w)
    if !w.hijacked {
        w.Close()
    }
}

func (srv *Server) ReadQUIC(stream quic.Stream, timeout time.Duration) ([]byte, error) {
    // Copied from readTCP():
    // If we race with ShutdownContext, the read deadline may
    // have been set in the distant past to unblock the read
    // below. We must not override it, otherwise we may block
    // ShutdownContext.
    srv.lock.RLock()
    if srv.started {
        stream.SetReadDeadline(time.Now().Add(timeout))
    }
    srv.lock.RUnlock()

    var length uint16
    if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
        return nil, err
    }

    m := make([]byte, length)
    if _, err := io.ReadFull(stream, m); err != nil {
        return nil, err
    }

    return m, nil
}
