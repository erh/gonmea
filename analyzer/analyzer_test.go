package analyzer

import (
	"os"
	"testing"

	"go.viam.com/test"

	"github.com/erh/gonmea/common"	
)

func TestParse(t *testing.T) {

	logger := common.NewLogger(os.Stderr)
	
	s := "!PDGY,130567,6,200,255,25631.18,RgPczwYAQnYeAB4AAAADAAAAAABQbiMA"
	m, err := ParseLine(s, false, logger)
	test.That(t, err, test.ShouldBeNil)

	a, err := NewAnalyzer(&Config{Logger: logger})
	test.That(t, err, test.ShouldBeNil)
	
	f, err := a.ConvertFields(m)
	test.That(t, err, test.ShouldBeNil)

	test.That(t, len(f), test.ShouldBeGreaterThan, 0)
}
