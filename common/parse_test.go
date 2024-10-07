package common

import (
	"testing"
	"time"

	"go.viam.com/test"
)

func TestParseTimestamp(t *testing.T) {
	ts, err := ParseTimestamp("04 Sep 24 15:14 +1234")
	test.That(t, err, test.ShouldBeNil)
	test.That(t, ts, test.ShouldEqual, time.Date(2024, time.September, 4, 15, 14, 1, 234000000, time.Local))
}
