// Package main is an example of using analyzer as a library
package main

import (
	"io"
	"os"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

func main() {
	logger := common.NewLogger(io.Discard)
	conf := analyzer.NewConfigForLibrary(os.Stdout, io.Discard, logger)

	var err error
	conf.InFile, err = os.Open("./analyzer/tests/pgn-test.in")
	if err != nil {
		panic(err)
	}
	ana, err := analyzer.NewAnalyzer(conf)
	if err != nil {
		panic(err)
	}
	if err := ana.Run(); err != nil {
		panic(err)
	}
}
