module nikand.dev/go/socks5/cmd/socks5

go 1.21

toolchain go1.21.4

replace nikand.dev/go/socks5 => ../../

require (
	github.com/nikandfor/hacked v0.0.0-20231207014854-3b383967fdf4
	nikand.dev/go/cli v0.0.0-20231112170903-c354aca481d7
	nikand.dev/go/graceful v0.0.0-20231125093149-1a6f0008cc34
	nikand.dev/go/socks5 v0.0.0-00010101000000-000000000000
	tlog.app/go/errors v0.9.0
	tlog.app/go/tlog v0.23.1
)

require (
	golang.org/x/sys v0.17.0 // indirect
	golang.org/x/term v0.17.0 // indirect
	tlog.app/go/eazy v0.3.0 // indirect
	tlog.app/go/loc v0.6.1 // indirect
)
