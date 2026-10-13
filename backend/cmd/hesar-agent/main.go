//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/Meytiz/HESAR/backend/internal/provision"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
)

var Version = "dev"

func main() {
	socket := flag.String("socket", provision.SocketPath, "Unix control socket")
	state := flag.String("state", "/var/lib/hesar-agent", "Private state directory")
	cores := flag.String("cores", "/usr/local/lib/hesar/cores", "Trusted packaged cores directory")
	account := flag.String("user", "hesar", "Authorized local account")
	version := flag.Bool("version", false, "Print version")
	flag.Parse()
	if *version {
		fmt.Println("HESAR Network Agent", Version)
		return
	}
	u, err := user.Lookup(*account)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil {
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := provision.ServeAgent(ctx, *socket, *state, *cores, uint32(uid), uint32(gid)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
