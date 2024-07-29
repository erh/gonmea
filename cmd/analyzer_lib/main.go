// Package main is an example of using analyzer as a library
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

func main() {
	err := realMain()
	if err != nil {
		panic(err)
	}
}

func realMain() error {
	if len(os.Args) != 2 {
		return errors.New("need file/path/net to parse")
	}

	path := os.Args[1]
	if strings.HasPrefix(path, "net:") {
		host := path[4:]
		conn, err := net.Dial("tcp", host)
		if err != nil {
			return fmt.Errorf("couldn't connect to host (%s): %w", host, err)
		}
		return processData(conn)
	}

	dataFile, err := os.Open(os.Args[1])
	if err != nil {
		return err
	}

	return processData(dataFile)
}

func processData(in io.ReadCloser) error {
	//nolint:errcheck
	defer in.Close()

	conf := analyzer.NewConfig(common.NewLogger(io.Discard))
	analyzer, err := analyzer.NewAnalyzer(conf)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(in)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		line = []byte(strings.TrimSpace(string(line)))
		if len(line) == 0 {
			continue
		}
		msg, hasMsg, err := analyzer.ProcessMessage(line)
		if err != nil {
			return err
		}
		if !hasMsg {
			continue
		}
		md, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(md))
	}
}
