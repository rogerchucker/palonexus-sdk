// SPDX-License-Identifier: MIT

package main

import (
	"os"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
