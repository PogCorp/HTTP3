# PogHTTP

A simple implementation of the HTTP/3.0 protocol that is agnostic with respect to it's QUIC implementation.

# Adapter

To allow the use of multiple implementations of QUIC, the Design Pattern _Adapter_ was used. Also since most implementations of QUIC are in C or C++, the library [cgo](https://pkg.go.dev/cmd/cgo@go1.23.3) was used through out most of the project.

# Examples
The directory _./example_ contains a sample that uses
[quic-go](https://github.com/quic-go/quic-go) library for QUIC communication.

To use it follow the next steps:

```
cd ./example
go build main.go
./main -c /path/to/certificate.crt -k /path/to/private.key
```

The program starts a HTTP server that returns the current time.

Other samples of QUIC using the _Adapter_ are also provided:
- Using [quic-go](https://github.com/quic-go/quic-go):

    https://github.com/PogCorp/HTTP3/blob/develop/pkg/quic/quicgo/cmd/echo_quicgo.go

- Using [LSQUIC](https://github.com/litespeedtech/lsquic):

    https://github.com/PogCorp/HTTP3/blob/develop/pkg/quic/lsquic/cmd/echo.go
