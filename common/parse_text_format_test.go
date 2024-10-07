package common

import (
	"go.viam.com/test"
	"testing"
)

func TestNavLink2a(t *testing.T) {
	p := navLink2Parser{}
	m := RawMessage{}

	msgData := "!PDGY,130567,6,200,255,25631.18,RgPczwYAQnYeAB4AAAADAAAAAABQbiMA"
	test.That(t, p.Detect(msgData), test.ShouldBeTrue)
	err := p.Parse(msgData, &m)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, len(m.Data), test.ShouldEqual, 24)
	test.That(t, m.PGN, test.ShouldEqual, 130567)

	msgData = "!PDGY,126998,6,200,255,7525.87,BQFpZDEFAWlkMhoBU3BvdFplcm8gUmV2ZXJzZSBPc21vc2lz"
	test.That(t, p.Detect(msgData), test.ShouldBeTrue)
	err = p.Parse(msgData, &m)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, len(m.Data), test.ShouldEqual, 36)
	test.That(t, m.PGN, test.ShouldEqual, 126998)

	msgData = "!PDGY,126998,6,200,255,7525.87,050169643105016964321A0153706F745A65726F2052657665727365204F736D6F736973"
	test.That(t, p.Detect(msgData), test.ShouldBeTrue)
	err = p.Parse(msgData, &m)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, m.PGN, test.ShouldEqual, 126998)
	test.That(t, len(m.Data), test.ShouldEqual, 36)

	test.That(t, p.Detect("asd"), test.ShouldBeFalse)
}
