package analyzer

import (
	"errors"
	"testing"
	"time"

	"go.viam.com/rdk/logging"
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
		PGN:         130567,
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
		msg.CachedRawData = nil
		test.That(t, format, test.ShouldEqual, RawFormatNavLink2)
		test.That(t, msg, test.ShouldResemble, expected)
	})

	t.Run("preset parser format", func(t *testing.T) {
		msg, err := ParseMessageWithFormat(msgData, RawFormatNavLink2)
		test.That(t, err, test.ShouldBeNil)
		msg.CachedRawData = nil
		test.That(t, msg, test.ShouldResemble, expected)

		// try it again
		msg, err = ParseMessageWithFormat(msgData, RawFormatNavLink2)
		test.That(t, err, test.ShouldBeNil)
		msg.CachedRawData = nil
		test.That(t, msg, test.ShouldResemble, expected)
	})

	t.Run("invalid format for data is ignored", func(t *testing.T) {
		_, err := ParseMessageWithFormat(msgData, RawFormatGarminCSV2)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, errors.Is(err, errExpectedOneMessage), test.ShouldBeTrue)
	})
}

func TestDYParse(t *testing.T) {
	logger := logging.NewTestLogger(t)
	parser, err := NewAnalyzer(NewConfig(logger))
	test.That(t, err, test.ShouldBeNil)

	msg, finished, err := parser.ProcessMessage([]byte("$PDGY,000000,0,0,2,28830,0,0"))
	test.That(t, err, test.ShouldBeNil)
	test.That(t, finished, test.ShouldBeTrue)
	test.That(t, msg, test.ShouldBeNil)
}

func TestSZParse(t *testing.T) {

	// this is hex encoded
	//msgData := []byte("!PDGY,126998,6,200,255,7525.87,050169643105016964321A0153706F745A65726F2052657665727365204F736D6F736973")

	// this is base64 encoded
	msgData := []byte("!PDGY,126998,6,200,255,7525.87,BQFpZDEFAWlkMhoBU3BvdFplcm8gUmV2ZXJzZSBPc21vc2lz")

	logger := logging.NewTestLogger(t)
	p, err := NewAnalyzer(NewConfig(logger))
	test.That(t, err, test.ShouldBeNil)

	msg, finished, err := p.ProcessMessage(msgData)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, finished, test.ShouldBeTrue)
	test.That(t, len(msg.Fields), test.ShouldEqual, 3)
	test.That(t, msg.Fields["Manufacturer Information"], test.ShouldEqual, "SpotZero Reverse Osmosis")

}
