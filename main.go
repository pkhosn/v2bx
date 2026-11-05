package main

import (
	"github.com/pkhosn/v2bx/cmd"
	"os"
)

func main() {
	if cmd.Run() != nil {
		os.Exit(1)
	}
}
