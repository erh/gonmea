// Package main is an example of using analyzer as a library
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/erh/gonmea/analyzer"
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

	reader, err := analyzer.NewMessageReader(in)
	if err != nil {
		return err
	}

	for {
		msg, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		md, err := json.MarshalIndent(msg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(md))
	}
}
