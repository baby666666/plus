package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
)

const version = "1.0.2"

func main() { os.Exit(cli(os.Args[1:])) }
func cli(args []string) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Printf("nr-hy2-reverse %s protocol=%d\n", version, protocolVersion)
		return 0
	}
	if len(args) < 1 || (args[0] != "run" && args[0] != "check" && args[0] != "check-ports") {
		fmt.Fprintln(os.Stderr, "usage: nr-hy2-reverse run|check|check-ports -config FILE [-exclude-pid PID]")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("config", "", "configuration file")
	exclude := flags.Int("exclude-pid", 0, "verified previous worker (check-ports only)")
	if flags.Parse(args[1:]) != nil || *path == "" || flags.NArg() != 0 || *exclude < 0 || (args[0] != "check-ports" && *exclude != 0) {
		return 2
	}
	c, err := loadConfig(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if args[0] == "check" {
		return 0
	}
	if args[0] == "check-ports" {
		if err = checkPorts(c, *exclude); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(32 << 20)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	stat := newTracker(c)
	defer stat.finish()
	if c.Mode == "server" {
		err = runServer(ctx, c, stat, productionTimings)
	} else {
		err = runClient(ctx, c, stat, productionTimings)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
