package doq

import (
    "context"
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "encoding/pem"
    "io"
    "math/big"
    "net"
    "sync"
    "testing"
    "time"

    "github.com/miekg/dns"

    "github.com/quic-go/quic-go"
)

func RunLocalServer(laddr string, quicConfig *quic.Config, config *tls.Config) (*Server, string, error) {
    pc, err := net.ListenPacket("udp", laddr)
    if err != nil {
        return nil, "", err
    }

    server := &Server{
        PacketConn: pc,

        QuicConfig: quicConfig,
        TLSConfig:  config,

        ReadTimeout:  time.Minute,
        WriteTimeout: time.Minute,
    }

    done := make(chan error, 1)

    go func() {
        server.NotifyStartedFunc = func() {
            done <- nil
        }
        done <- server.ActivateAndServe()
        pc.Close()
    }()

    return server, pc.LocalAddr().String(), <-done
}

func generateTLSConfig() *tls.Config {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        panic(err)
    }
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(time.Hour * 86400),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    if err != nil {
        panic(err)
    }
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        panic(err)
    }
    return &tls.Config{
        Certificates: []tls.Certificate{tlsCert},
    }
}

func NewClient(addr string) (quic.Connection, error) {
    tlsConf := &tls.Config{
        InsecureSkipVerify: true,
        NextProtos:         []string{"doq"},
    }
    conn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
    if err != nil {
        return nil, err
    }
    return conn, nil
}

func Exchange(t *testing.T, s quic.Stream, m *dns.Msg) *dns.Msg {
    b, err := m.Pack()
    if err != nil {
        t.Fatal(err)
    }

    var length uint16
    length = uint16(len(b))
    if err := binary.Write(s, binary.BigEndian, length); err != nil {
        t.Fatal(err)
    }

    _, err = s.Write(b)
    if err != nil {
        t.Fatal(err)
    }

    if err := binary.Read(s, binary.BigEndian, &length); err != nil {
        t.Fatal(err)
    }

    r := make([]byte, length)
    if _, err := io.ReadFull(s, r); err != nil {
        t.Fatal(err)
    }

    response := new(dns.Msg)
    if err = response.Unpack(r); err != nil {
        t.Fatal(err)
    }

    return response
}

func TestSimpleQuery(t *testing.T) {
    dns.HandleFunc("example.com.", HelloServer)
    defer dns.HandleRemove("example.com.")

    s, addr, err := RunLocalServer(":0", nil, generateTLSConfig())
    if err != nil {
        t.Fatalf("unable to run test server: %v", err)
    }
    defer s.Shutdown()

    conn, err := NewClient(addr)
    if err != nil {
        t.Fatal(err)
    }
    defer conn.CloseWithError(0, "")

    stream, err := conn.OpenStreamSync(context.Background())
    if err != nil {
        t.Fatal(err)
    }
    defer stream.Close()

    m := new(dns.Msg)
    m.SetQuestion("example.com.", dns.TypeTXT)

    r := Exchange(t, stream, m)
    if len(r.Extra) == 0 {
        t.Fatal("failed to exchange")
    }
    txt := r.Extra[0].(*dns.TXT).Txt[0]
    if txt != "Hello example" {
        t.Error("unexpected result for example.com", txt, "!= Hello example")
    }
}

func TestBlastOneHundredQueriesOverOneConn(t *testing.T) {
    dns.HandleFunc("example.com.", HelloServer)
    defer dns.HandleRemove("example.com.")

    s, addr, err := RunLocalServer(":0", nil, generateTLSConfig())
    if err != nil {
        t.Fatalf("unable to run test server: %v", err)
    }
    defer s.Shutdown()

    conn, err := NewClient(addr)
    if err != nil {
        t.Fatal(err)
    }
    defer conn.CloseWithError(0, "")

    m := new(dns.Msg)
    m.SetQuestion("example.com.", dns.TypeTXT)

    var wg sync.WaitGroup

    for i := 0; i < 100; i++ {
        go func() {
            stream, err := conn.OpenStreamSync(context.Background())
            if err != nil {
                t.Fatal(err)
            }
            defer stream.Close()

            r := Exchange(t, stream, m)
            if len(r.Extra) == 0 {
                t.Fatal("failed to exchange")
            }
            txt := r.Extra[0].(*dns.TXT).Txt[0]
            if txt != "Hello example" {
                t.Error("unexpected result for example.com", txt, "!= Hello example")
            }

            wg.Done()
        }()
        wg.Add(1)
    }
    wg.Wait()
}

func HelloServer(w dns.ResponseWriter, req *dns.Msg) {
    m := new(dns.Msg)
    m.SetReply(req)

    m.Extra = make([]dns.RR, 1)
    m.Extra[0] = &dns.TXT{Hdr: dns.RR_Header{Name: m.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: []string{"Hello example"}}
    w.WriteMsg(m)
}
