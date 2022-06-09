# DNS-over-QUIC (DoQ, RFC9250) support for miekg/dns

WIP

Based on `dns.Server`, using lucas-clemente/quic-go to support DoQ.

Example:
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

Caveats:
- removed `doq.UDPSize`, DoQ is fixed at max size (64k)
- TSIG supported somewhat but untested
- Add `doq.QuicConfig` (`quic.Config`), used when creating `quic.Listener`
- `doq.Reader` interface different from `dns.Reader`, affecting `.DecorateReader`

Protocols TODO:
- send STREAM FIN after response?
- check for STREAM FIN from client on query?
- enforce DNS msg id == 0?
- reject more then one query over 1 stream?
- rejcet edns tcp keep alive?
- unidirectional streams not allowed?

## License

```
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
```
