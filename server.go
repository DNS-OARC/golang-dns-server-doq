// DNS-over-QUIC Server (RFC9250).

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

    "github.com/quic-go/quic-go"
)

// A Server defines parameters for running an DNS-over-QUIC server.
type Server struct {
    // Address to listen on, ":853" if empty.
    Addr string
    // Set to "doq" for DNS-over-QUIC (RFC9250).
    Net string
    // QUIC connection configuration.
    QuicConfig *quic.Config
    // QUIC Listener to use, this is to aid in systemd's socket activation.
    Listener *quic.Listener
    // Packet "Listener" to use, this is to aid in systemd's socket activation.
    PacketConn net.PacketConn
    // TLS connection configuration.
    TLSConfig *tls.Config
    // Handler to invoke, dns.DefaultServeMux if nil.
    Handler dns.Handler
    // The read timeout value for new connections, defaults to 2 * time.Second.
    ReadTimeout time.Duration
    // The write timeout value for new connections, defaults to zero (will not time out).
    WriteTimeout time.Duration
    // An implementation of the dns.TsigProvider interface. If defined it replaces TsigSecret and is used for all TSIG operations.
    TsigProvider dns.TsigProvider
    // Secret(s) for Tsig map[<zonename>]<base64 secret>. The zonename must be in canonical form.
    TsigSecret map[string]string
    // If NotifyStartedFunc is set it is called once the server has started listening.
    NotifyStartedFunc func()
    // Whether to set the SO_REUSEPORT socket option, only used with ListenAndServe.
    ReusePort bool
    // AcceptMsgFunc will check the incoming message and will reject it early in the process.
    // By default dns.DefaultMsgAcceptFunc will be used.
    MsgAcceptFunc dns.MsgAcceptFunc

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
}

func unlockOnce(l sync.Locker) func() {
    var once sync.Once
    return func() { once.Do(l.Unlock) }
}

// ListenAndServe starts a DNS-over-QUIC nameserver on the configured address in *Server.
//
// Returns on error or when Shutdown.
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

// ActivateAndServe starts a DNS-over-QUIC nameserver with the already configured PacketConn or Listener.
//
// Checks if Listener is set, otherwise it will use PacketConn to create a quic.Listener.
// Returns on error or when Shutdown.
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

// Shutdown shuts down a server using context.Background().
func (srv *Server) Shutdown() error {
    return srv.ShutdownContext(context.Background())
}

// ShutdownContext shuts down a server and waits for ListenAndServe or ActivateAndServe to finish.
//
// ctx can be used to cancel the wait.
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

    srv.Handler.ServeDNS(w, req)
}

type response struct {
    closed         bool
    tsigTimersOnly bool
    tsigStatus     error
    tsigRequestMAC string
    tsigProvider   dns.TsigProvider
    tsigSecret     map[string]string
    doq            quic.Stream
    writer         dns.Writer
    localAddr      net.Addr
    remoteAddr     net.Addr

    connectionState tls.ConnectionState
}

func (w *response) WriteMsg(m *dns.Msg) (err error) {
    if w.closed {
        return errors.New("doq: WriteMsg called after Close")
    }

    var data []byte
    if w.tsigProvider != nil {
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

func (w *response) LocalAddr() net.Addr { return w.localAddr }

func (w *response) RemoteAddr() net.Addr { return w.remoteAddr }

func (w *response) TsigStatus() error { return w.tsigStatus }

func (w *response) TsigTimersOnly(b bool) { w.tsigTimersOnly = b }

func (w *response) Hijack() {}

func (w *response) Close() error {
    if w.closed {
        return errors.New("doq: stream already closed")
    }
    w.closed = true

    return w.doq.Close()
}

func (w *response) ConnectionState() *tls.ConnectionState {
    return &w.connectionState
}

type connection struct {
    lock    sync.RWMutex
    conn    quic.Connection
    closed  bool
    streams map[quic.Stream]struct{}
    wg      sync.WaitGroup
}

func (srv *Server) serveQUIC(l *quic.Listener) error {
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
        c := &connection{conn: conn, streams: make(map[quic.Stream]struct{})}
        srv.conns[c] = struct{}{}
        srv.lock.Unlock()
        wg.Add(1)
        go srv.serveQUICConn(&wg, c)
    }
    return nil
}

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

func (srv *Server) serveQUICStream(c *connection, stream quic.Stream) {
    defer func() {
        c.lock.Lock()
        delete(c.streams, stream)
        c.lock.Unlock()
        c.wg.Done()
    }()

    w := &response{
        doq:        stream,
        localAddr:  c.conn.LocalAddr(),
        remoteAddr: c.conn.RemoteAddr(),
        tsigSecret: srv.TsigSecret,

        connectionState: c.conn.ConnectionState().TLS,
    }
    defer w.Close()
    w.writer = w

    stream.SetReadDeadline(time.Now().Add(srv.ReadTimeout))
    stream.SetWriteDeadline(time.Now().Add(srv.WriteTimeout))

    var length uint16
    if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
        return
    }

    m := make([]byte, length)
    if _, err := io.ReadFull(stream, m); err != nil {
        return
    }

    srv.serveDNS(m, w)
}
