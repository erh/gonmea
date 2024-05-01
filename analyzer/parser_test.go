package analyzer

import (
	"testing"
	"time"

	"go.viam.com/test"

	"github.com/erh/gonmea/common"
)

func TestParser(t *testing.T) {
	s := []byte("!PDGY,130567,6,200,255,25631.18,RgPczwYAQnYeAB4AAAADAAAAAABQbiMA")
	m, format, err := ParseMessage(s)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, format, test.ShouldEqual, RawFormatNavLink2)
	test.That(t, m, test.ShouldResemble, &common.Message{
		Timestamp:   "25631.18",
		Priority:    6,
		Src:         200,
		Dst:         255,
		Pgn:         130567,
		Description: "Watermaker Input Setting and Status",
		Fields: map[string]interface{}{
			"Brine Water Flow":              0.0,
			"Emergency Stop":                "No",
			"Feed Pressure":                 0.0,
			"High Pressure Pump Status":     "No",
			"Low Pressure Pump Status":      "No",
			"Post-filter Pressure":          0.03,
			"Pre-filter Pressure":           0.03,
			"Product Solenoid Valve Status": "OK",
			"Product Water Flow":            0.0,
			"Product Water Temperature":     29.59000000000003,
			"Production Start/Stop":         "Yes",
			"Run Time":                      645 * time.Hour,
			"Salinity":                      6,
			"Salinity Status":               "Warning",
			"System High Pressure":          0.03,
			"System Status":                 "OK",
			"Watermaker Operating State":    "Initiating",
		},
	})
}
