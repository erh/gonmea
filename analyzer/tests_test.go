package analyzer

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestFiles(t *testing.T) {

	files, err := filepath.Glob("tests/*.in")
	test.That(t, err, test.ShouldBeNil)

	for _, fn := range files {
		t.Run(fmt.Sprintf("f %v", fn), func(t *testing.T) {
			logger := logging.NewTestLogger(t)

			f, err := os.Open(fn)
			test.That(t, err, test.ShouldBeNil)
			r := bufio.NewReader(f)

			conf := NewConfig(logger)
			ana, err := newAnalyzer(conf)
			test.That(t, err, test.ShouldBeNil)

			for {
				lineBytes, _, err := r.ReadLine()
				if err == io.EOF {
					break
				}
				test.That(t, err, test.ShouldBeNil)

				line := string(lineBytes)
				logger.Infof("going to parse line %v", line)

				_, _, err = ana.ProcessMessage(line)
				test.That(t, err, test.ShouldBeNil)
			}

		})
	}
}
