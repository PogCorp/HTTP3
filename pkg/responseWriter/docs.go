package responseWriter

// Implements the http.ResponseWriter interface
// this interface contains:
//  - Header(),
//  - Write([]byte),
//  - WriteHeader(int)
//
// The behaviour of which is described in [The Life of Write](https://github.com/golang/go/blob/245e95dfabd77f337373bf2d6bb47cd353ad8d74/src/net/http/server.go#L1559)
