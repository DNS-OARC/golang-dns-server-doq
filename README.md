# DNS-over-QUIC (DoQ, RFC9250) Server

WIP

In-use at https://cmdns.dev.dns-oarc.net/ instances:
```
$ kdig @77.72.225.247 ns.tcmdns.dev.dns-oarc.net AAAA +quic +short
2a01:3f0:0:57::247
$ q ns.tcmdns.dev.dns-oarc.net @quic://77.72.225.247 -i
ns.tcmdns.dev.dns-oarc.net. 1m A 77.72.225.247
ns.tcmdns.dev.dns-oarc.net. 1m AAAA 2a01:3f0:0:57::247
```

Protocols TODO:
- send STREAM FIN after response?
- check for STREAM FIN from client on query?
- enforce DNS msg id == 0?
- reject more then one query over 1 stream?
- rejcet edns tcp keep alive?
- unidirectional streams not allowed?

## Example

```
tlsConfig := tls.Config{
    Certificates: []tls.Certificate{...},
}
quicConfig := quic.Config{
    ...
}
srv := &doq.Server{Addr: addr, Net: "doq", QuicConfig: &quicConfig, TLSConfig: &config, Handler: ...}
srv.ListenAndServe()
```

## License

```
MIT License

Copyright (c) 2024 OARC, Inc.
```
