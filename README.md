# DNS-over-QUIC (DoQ, RFC9250) Server

WIP

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

Copyright (c) 2022 OARC, Inc.
```
