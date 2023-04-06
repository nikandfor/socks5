module github.com/nikandfor/socks5/cmd

go 1.18

replace github.com/nikandfor/socks5 => ../

require (
	github.com/nikandfor/cli v0.0.0-20230223182849-7e82897d9c99
	github.com/nikandfor/errors v0.8.0
	github.com/nikandfor/graceful v0.0.0-20230406213650-2ff8f1b6f182
	github.com/nikandfor/hacked v0.0.0-20230404201721-a8a0d1024c87
	github.com/nikandfor/socks5 v0.0.0-00010101000000-000000000000
	github.com/nikandfor/tlog v0.21.0
)

require (
	github.com/nikandfor/loc v0.5.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/term v0.5.0 // indirect
)
