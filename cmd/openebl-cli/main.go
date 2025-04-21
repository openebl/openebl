package main

import (
	"os"

	"github.com/openebl/openebl/cmd/openebl-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
