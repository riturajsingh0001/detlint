// Command detlint is a linter and test harness for detection rules.
package main

import (
	"os"

	"github.com/riturajsingh0001/detlint/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
