package analyzer

import (
	"testing"
	"time"

	"go.viam.com/test"

	"github.com/erh/gonmea/common"
)

var (
	shortMessage = &common.Message{
		Timestamp:   time.Date(2022, time.September, 10, 12, 10, 16, 614000000, time.UTC),
		Priority:    6,
		Src:         5,
		Dst:         255,
		PGN:         60928,
		Description: "ISO Address Claim",
		Fields: map[string]interface{}{
			"Arbitrary address capable": 1,
			"Device Class":              "Steering and Control surfaces",
			"Device Function":           "Rudder",
			"Device Instance Lower":     0,
			"Device Instance Upper":     0,
			"Industry Group":            "Marine",
			"Manufacturer Code":         "Navico",
			"System Instance":           0,
			"Unique Number":             1088507,
		},
	}
	longMessage = &common.Message{
		Timestamp:   time.Date(2022, time.September, 28, 11, 36, 59, 668000000, time.UTC),
		Priority:    3,
		Src:         0,
		Dst:         255,
		PGN:         129029,
		Description: "GNSS Position Data",
		Fields: map[string]interface{}{
			"Altitude":           90.98460299999999,
			"Date":               time.Date(2013, time.March, 1, 0, 0, 0, 0, time.UTC),
			"GNSS type":          "GPS+SBAS/WAAS",
			"Geoidal Separation": -33.63,
			"HDOP":               1.11,
			"Integrity":          "No integrity checking",
			"Latitude":           42.496768422109845,
			"Longitude":          -71.58366365704198,
			"Method":             "GNSS fix",
			"Number of SVs":      8,
			"PDOP":               1.9000000000000001,
			"Reference Stations": 0,
			"SID":                231,
			"Time":               time.Duration(70192000000000),
		},
		Sequence: 6,
	}
)

func TestMarshalMessageToRaw(t *testing.T) {
	rawMsg, err := MarshalMessageToRaw(longMessage)
	test.That(t, err, test.ShouldBeNil)

	rtMsg, ok, err := ConvertRawMessage(rawMsg)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, ok, test.ShouldBeTrue)
	rtMsg.CachedRawData = nil

	test.That(t, rtMsg, test.ShouldResemble, longMessage)
}

func TestMarshalMessageToFormat(t *testing.T) {
	for _, tc := range []struct {
		Case    string
		Multi   common.MultiPackets
		Message *common.Message
	}{
		// separate
		{
			"short plain separate",
			common.MultiPacketsSeparate,
			shortMessage,
		},
		{
			"long plain separate",
			common.MultiPacketsSeparate,
			longMessage,
		},
		{
			"short fast separate",
			common.MultiPacketsSeparate,
			shortMessage,
		},
		{
			"long fast separate",
			common.MultiPacketsSeparate,
			longMessage,
		},
		{
			"short plainfast separate",
			common.MultiPacketsSeparate,
			shortMessage,
		},
		{
			"long plainfast separate",
			common.MultiPacketsSeparate,
			longMessage,
		},

		// coalesced
		{
			"short plain coalesced",
			common.MultiPacketsCoalesced,
			shortMessage,
		},
		{
			"long plain coalesced",
			common.MultiPacketsCoalesced,
			longMessage,
		},
		{
			"short fast coalesced",
			common.MultiPacketsCoalesced,
			shortMessage,
		},
		{
			"long fast coalesced",
			common.MultiPacketsCoalesced,
			longMessage,
		},
		{
			"short plainfast coalesced",
			common.MultiPacketsCoalesced,
			shortMessage,
		},
		{
			"long plainfast coalesced",
			common.MultiPacketsCoalesced,
			longMessage,
		},
	} {
		t.Run(tc.Case, func(t *testing.T) {
			_, err := MarshalMessage(tc.Message)
			test.That(t, err, test.ShouldBeNil)
			/*
				numLines := bytes.Count(md, []byte{'\n'})
				if tc.Multi == common.MultiPacketsCoalesced {
					test.That(t, numLines, test.ShouldEqual, 1)
				} else {
					if tc.Message == shortMessage {
						test.That(t, numLines, test.ShouldEqual, 1)
					} else {
						test.That(t, numLines, test.ShouldBeGreaterThan, 1)
					}
				}

				reader, err := NewMessageReader(bytes.NewReader(md))
				test.That(t, err, test.ShouldBeNil)
				rtMsg, err := reader.Read()
				test.That(t, err, test.ShouldBeNil)
				rtMsg.CachedRawData = nil
				if tc.Multi == common.MultiPacketsCoalesced {
					// sequence makes no sense here
					rtMsg.Sequence = tc.Message.Sequence
				}

				test.That(t, rtMsg, test.ShouldResemble, tc.Message)

				_, err = reader.Read()
				test.That(t, err, test.ShouldBeError, io.EOF)
			*/
		})
	}
}

func TestMarshalMessageToSingleOrFastRaw(t *testing.T) {
	for _, tc := range []struct {
		Case    string
		Message *common.Message
	}{
		// separate
		{
			"short",
			shortMessage,
		},
		{
			"long",
			longMessage,
		},
		{
			"max uint64 field",
			&common.Message{
				Timestamp:   time.Date(2024, time.September, 28, 11, 36, 59, 668000000, time.UTC),
				Priority:    2,
				Src:         170,
				Dst:         255,
				PGN:         126985,
				Description: "Alert Text",
				Fields: map[string]interface{}{
					"Alert Type":                      "Warning",
					"Alert Category":                  "Technical",
					"Alert System":                    17,
					"Alert Sub-System":                18,
					"Alert ID":                        517,
					"Data Source Network ID NAME":     19,
					"Data Source Instance":            0,
					"Data Source Index-Source":        0,
					"Alert Occurrence Number":         0,
					"Language ID":                     "English (US)",
					"Alert Text Description":          "advise",
					"Alert Location Text Description": "vessel_instr_1",
				},
			},
		},
	} {
		t.Run(tc.Case, func(t *testing.T) {
			raws, err := MarshalMessageToSingleOrFastRaw(tc.Message)
			test.That(t, err, test.ShouldBeNil)

			ana, err := newOneOffAnalyzer()
			test.That(t, err, test.ShouldBeNil)

			for _, raw := range raws[:len(raws)-1] {
				_, hasMsg, err := ana.ConvertRawMessage(raw)
				test.That(t, err, test.ShouldBeNil)
				test.That(t, hasMsg, test.ShouldBeFalse)
			}
			rtMsg, hasMsg, err := ana.ConvertRawMessage(raws[len(raws)-1])
			test.That(t, err, test.ShouldBeNil)
			test.That(t, hasMsg, test.ShouldBeTrue)
			rtMsg.CachedRawData = nil

			test.That(t, rtMsg, test.ShouldResemble, tc.Message)
		})
	}
}
