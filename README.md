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

There is a cmd/socks5/main.go which can be treated as an example. It can also be used as a command.

```
go install nikand.dev/go/socks5/cmd/socks5@latest # install

socks5 server -l :1080 -auth user:pass,user2:pass # auth is optional, without it none auth is used
```

## Benchmarks

Generated on Apple Air M1

```
goos: darwin
goarch: arm64
pkg: github.com/nikandfor/socks5
BenchmarkServerHandshake-8   	24888297	        48.11 ns/op	       8 B/op	       1 allocs/op
BenchmarkClientHandshake-8   	39229520	        29.58 ns/op	       8 B/op	       1 allocs/op
BenchmarkWriteRequest-8      	23223670	        51.34 ns/op	      24 B/op	       1 allocs/op
BenchmarkReadRequestName-8   	12071508	       100.1 ns/op	      56 B/op	       3 allocs/op
BenchmarkReadRequestIP16-8   	13279104	        90.60 ns/op	      88 B/op	       3 allocs/op
```
