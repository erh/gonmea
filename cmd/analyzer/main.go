// Package main is an example of using analyzer as a CLI
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

func main() {
	conf, cont, err := analyzer.ParseArgs(os.Args)
	handleErr(err)
	defer func() {
		//nolint:errcheck
		conf.Logger.Sync()
	}()
	if !cont {
		return
	}
	ana, err := analyzer.NewAnalyzer(conf)
	handleErr(err)
	handleErr(ana.Run())
}

func handleErr(err error) {
	if err == nil {
		return
	}
	var exitErr *common.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	fmt.Fprint(os.Stderr, err.Error())
	os.Exit(1)
}
