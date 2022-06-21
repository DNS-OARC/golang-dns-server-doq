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
    "sync"
    "syscall"
    "time"

    "golang.org/x/sys/unix"

    "github.com/miekg/dns"

    "github.com/lucas-clemente/quic-go"
)

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
    // QUIC connection configuration
    QuicConfig *quic.Config
    // QUIC Listener to use, this is to aid in systemd's socket activation.
    Listener quic.Listener
    // Packet "Listener" to use, this is to aid in systemd's socket activation.
    PacketConn net.PacketConn
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
    // An implementation of the TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
    TsigProvider dns.TsigProvider
    // Secret(s) for Tsig map[<zonename>]<base64 secret>. The zonename must be in canonical form (lowercase, fqdn, see RFC 4034 Section 6.2).
    TsigSecret map[string]string
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
//
// This will overwrite Listener and PacketConn.
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
    ql, err := quic.Listen(l, srv.TLSConfig, srv.QuicConfig)
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
//
// It will first check if Listener can be used, otherwise it will use
// PacketConn to create a quic.Listener and set Listener.
func (srv *Server) ActivateAndServe() error {
    unlock := unlockOnce(&srv.lock)
    srv.lock.Lock()
    defer unlock()

    if srv.started {
        return errors.New("doq: server already started")
    }

    srv.init()

    if srv.Listener != nil {
        srv.started = true
        unlock()
        return srv.serveQUIC(srv.Listener)
    }
    if srv.PacketConn != nil {
        // Check PacketConn interface's type is valid and value
        // is not nil
        if t, ok := srv.PacketConn.(*net.UDPConn); ok && t == nil {
            return errors.New("doq: PacketConn is not a UDP connection")
        }

        if srv.TLSConfig == nil || (len(srv.TLSConfig.Certificates) == 0 && srv.TLSConfig.GetCertificate == nil) {
            return errors.New("doq: neither Certificates nor GetCertificate set in Config")
        }
        srv.TLSConfig.NextProtos = []string{"doq", "doq-i03"}

        ql, err := quic.Listen(srv.PacketConn, srv.TLSConfig, srv.QuicConfig)
        if err != nil {
            return err
        }
        srv.Listener = ql
        srv.started = true
        unlock()
        return srv.serveQUIC(ql)
    }

    return errors.New("doq: neither Listener nor PacketConn was set")
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
        rw.lock.Lock()
        rw.closed = true
        rw.conn.CloseWithError(0, "")
        rw.lock.Unlock()
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

    w.tsigStatus = nil
    if w.tsigProvider != nil {
        if t := req.IsTsig(); t != nil {
            w.tsigStatus = dns.TsigVerifyWithProvider(m, w.tsigProvider, "", false)
            w.tsigTimersOnly = false
            w.tsigRequestMAC = t.MAC
        }
    } else if w.tsigSecret != nil {
        if t := req.IsTsig(); t != nil {
            tsig := req.Extra[len(req.Extra)-1].(*dns.TSIG)
            key, ok := w.tsigSecret[tsig.Hdr.Name]
            if ok {
                w.tsigStatus = dns.TsigVerify(m, key, "", false)
            } else {
                w.tsigStatus = dns.ErrSecret
            }
            w.tsigTimersOnly = false
            w.tsigRequestMAC = t.MAC
        }
    }

    srv.Handler.ServeDNS(w, req) // Writes back to the client
}

// Response struct for ResponseWriter interface
type response struct {
    closed         bool // connection has been closed
    hijacked       bool // connection has been hijacked by handler
    tsigTimersOnly bool
    tsigStatus     error
    tsigRequestMAC string
    tsigProvider   dns.TsigProvider
    tsigSecret     map[string]string
    doq            quic.Stream // i/o connection if QUIC was used
    writer         dns.Writer  // writer to output the raw DNS bits
    localAddr      net.Addr
    remoteAddr     net.Addr

    connectionState tls.ConnectionState
}

// WriteMsg implements the ResponseWriter.WriteMsg method.
func (w *response) WriteMsg(m *dns.Msg) (err error) {
    if w.closed {
        return errors.New("doq: WriteMsg called after Close")
    }

    var data []byte
    if w.tsigProvider != nil { // if no provider, dont check for the tsig (which is a longer check)
        if t := m.IsTsig(); t != nil {
            data, w.tsigRequestMAC, err = dns.TsigGenerateWithProvider(m, w.tsigProvider, w.tsigRequestMAC, w.tsigTimersOnly)
            if err != nil {
                return err
            }
            _, err = w.writer.Write(data)
            return err
        }
    } else if w.tsigSecret != nil {
        if t := m.IsTsig(); t != nil {
            tsig := m.Extra[len(m.Extra)-1].(*dns.TSIG)
            key, ok := w.tsigSecret[tsig.Hdr.Name]
            if !ok {
                return dns.ErrSecret
            }
            data, w.tsigRequestMAC, err = dns.TsigGenerate(m, key, w.tsigRequestMAC, w.tsigTimersOnly)
            if err != nil {
                return err
            }
            _, err = w.writer.Write(data)
            return err
        }
    }
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

// ConnectionState() implements the dns.ConnectionStater interface
func (w *response) ConnectionState() *tls.ConnectionState {
    return &w.connectionState
}

// A quic connection
type connection struct {
    lock    sync.RWMutex
    conn    quic.Connection
    closed  bool
    streams map[quic.Stream]struct{}
    wg      sync.WaitGroup
}

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
        if err != nil {
            if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
                continue
            }
            return err
        }
        srv.lock.Lock()
        if !srv.started {
            srv.lock.Unlock()
            conn.CloseWithError(0, "")
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
            if neterr, ok := err.(net.Error); ok && neterr.Temporary() {
                continue
            }
            break
        }
        c.lock.Lock()
        if c.closed {
            c.lock.Unlock()
            break
        }
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

    c.conn.CloseWithError(0, "")

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

        tsigSecret: srv.TsigSecret,

        connectionState: c.conn.ConnectionState().TLS.ConnectionState,
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
    if err == nil {
        srv.serveDNS(m, w)
    }
    if !w.hijacked {
        w.Close()
    }
}

// Default Reader.ReadQUIC() implementation
func (srv *Server) ReadQUIC(stream quic.Stream, timeout time.Duration) ([]byte, error) {
    // TODO: Do we need to read lock srv for this?
    stream.SetReadDeadline(time.Now().Add(timeout))

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
