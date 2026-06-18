package main

import (
	"fmt"
	"os"

	"github.com/ChristianF88/flokbn/cli"
)

func main() {
	if err := cli.App.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "flokbn:", err)
		os.Exit(1)
	}
}
