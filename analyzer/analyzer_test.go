package analyzer

import (
	"os"
	"testing"

	"go.viam.com/test"

	"github.com/erh/gonmea/common"	
)

func TestParse(t *testing.T) {
	s := "!PDGY,126998,6,200,255,32624.24,050169643105016964321A0153706F745A65726F2052657665727365204F736D6F736973"
	m, err := ParseLine(s, false, common.NewLogger(os.Stderr))
	test.That(t, err, test.ShouldBeNil)
	panic(m)
}
