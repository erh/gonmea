package analyzer

import (
	"errors"
	"io"
	"testing"
	"time"

	"go.viam.com/test"

	"github.com/erh/gonmea/common"
)

func TestParser(t *testing.T) {
	msgData := []byte("!PDGY,130567,6,200,255,25631.18,RgPczwYAQnYeAB4AAAADAAAAAABQbiMA")
	expected := &common.Message{
		Timestamp:   time.Time{}.Add(time.Microsecond * time.Duration(25631.18*1e3)),
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
	}

	t.Run("one shot", func(t *testing.T) {
		msg, format, err := ParseMessage(msgData)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, format, test.ShouldEqual, RawFormatNavLink2)
		test.That(t, msg, test.ShouldResemble, expected)
	})

	t.Run("preset parser format", func(t *testing.T) {
		parser, err := NewParserWithFormat(RawFormatNavLink2)
		test.That(t, err, test.ShouldBeNil)

		msg, err := parser.ParseMessage(msgData)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, msg, test.ShouldResemble, expected)

		// try it again
		msg, err = parser.ParseMessage(msgData)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, msg, test.ShouldResemble, expected)
	})

	t.Run("invalid format for data is ignored", func(t *testing.T) {
		parser, err := NewParserWithFormat(RawFormatGarminCSV2)
		test.That(t, err, test.ShouldBeNil)

		_, err = parser.ParseMessage(msgData)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, errors.Is(err, io.EOF), test.ShouldBeTrue)
	})
}
