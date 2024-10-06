package common

import (
	"testing"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestParseTimestamp(t *testing.T) {
	ts, err := ParseTimestamp("04 Sep 24 15:14 +1234")
	test.That(t, err, test.ShouldBeNil)
	test.That(t, ts, test.ShouldEqual, time.Date(2024, time.September, 4, 15, 14, 1, 234000000, time.Local))
}

func TestNavLink2a(t *testing.T) {
	logger := logging.NewTestLogger(t)
	m := RawMessage{}

	msgData := []byte("!PDGY,130567,6,200,255,25631.18,RgPczwYAQnYeAB4AAAADAAAAAABQbiMA")
	res := ParseRawFormatNavLink2(msgData, &m, logger)
	test.That(t, res, test.ShouldEqual, 0)
	test.That(t, len(m.Data), test.ShouldEqual, 24)
	test.That(t, m.PGN, test.ShouldEqual, 130567)

	msgData = []byte("!PDGY,126998,6,200,255,7525.87,BQFpZDEFAWlkMhoBU3BvdFplcm8gUmV2ZXJzZSBPc21vc2lz")
	res = ParseRawFormatNavLink2(msgData, &m, logger)
	test.That(t, res, test.ShouldEqual, 0)
	test.That(t, len(m.Data), test.ShouldEqual, 36)
	test.That(t, m.PGN, test.ShouldEqual, 126998)

	/*
		msgData = []byte("!PDGY,126998,6,200,255,7525.87,050169643105016964321A0153706F745A65726F2052657665727365204F736D6F736973")
		res = ParseRawFormatNavLink2(msgData, &m, logger)
		test.That(t, res, test.ShouldEqual, 0)
		test.That(t, m.PGN, test.ShouldEqual, 126998)
		test.That(t, len(m.Data), test.ShouldEqual, 36)
	*/
}
