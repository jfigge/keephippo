// Command keephippo is the console application and server for a
// Vault-compatible secrets manager. All subcommands live in internal/command.
package main

import (
	"os"

	"github.com/jfigge/keephippo/internal/command"
)

func main() {
	os.Exit(command.Execute())
}
