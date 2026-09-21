package main

import (
	"os"

	"gfw-x/internal/cli"
	"gfw-x/internal/version"
)

func main() {
	// Override version info from build flags is done via ldflags + package vars.
	_ = version.Info
	os.Exit(cli.Run(os.Args[1:]))
}
