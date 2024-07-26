[![Documentation](https://pkg.go.dev/badge/github.com/nikandfor/socks5)](https://pkg.go.dev/github.com/nikandfor/socks5?tab=doc)
[![Go workflow](https://github.com/nikandfor/socks5/actions/workflows/go.yml/badge.svg)](https://github.com/nikandfor/socks5/actions/workflows/go.yml)
[![CircleCI](https://circleci.com/gh/nikandfor/socks5.svg?style=svg)](https://circleci.com/gh/nikandfor/socks5)
[![codecov](https://codecov.io/gh/nikandfor/socks5/branch/master/graph/badge.svg)](https://codecov.io/gh/nikandfor/socks5)
[![Go Report Card](https://goreportcard.com/badge/github.com/nikandfor/socks5)](https://goreportcard.com/report/github.com/nikandfor/socks5)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nikandfor/socks5?sort=semver)

# socks5

This is a library designed for performant multiproxy implementations. This means
* Efficient code
* Low-level API
* Stateless objects
* Both client and server is implemented

# Example

There is a [cmd/socks5/main.go](cmd/socks5/main.go) which can be treated as an example. It can also be used as a command.

```
go install nikand.dev/go/socks5/cmd/socks5@latest # install

socks5 server -l :1080 -auth user:pass,user2:pass # auth is optional, without it none auth is used
```

## Benchmarks

Generated on Apple Macbook Air M1

```
goos: darwin
goarch: arm64
pkg: nikand.dev/go/socks5
BenchmarkServerHandshake-8        	36790387	        32.39 ns/op	       0 B/op	       0 allocs/op
BenchmarkClientHandshake-8        	56295850	        21.05 ns/op	       0 B/op	       0 allocs/op
BenchmarkWriteRequest-8           	37399100	        32.51 ns/op	       0 B/op	       0 allocs/op
BenchmarkReadRequestName-8        	16392350	        71.46 ns/op	      32 B/op	       2 allocs/op
BenchmarkReadRequestIP16-8        	22964949	        53.26 ns/op	      64 B/op	       1 allocs/op
BenchmarkReadRequestNetipIP16-8   	23116654	        51.40 ns/op	      32 B/op	       1 allocs/op
```
