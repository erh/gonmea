package common

import (
	"go.viam.com/test"
	"testing"
)

func TestPlain1(t *testing.T) {
	s := "2021-07-29T10:18:31.758Z,6,126208,36,0,7,02,82,ff,00,10,02,00"

	b, ok := DataLengthInPlainOrFast(s)
	test.That(t, ok, test.ShouldBeTrue)
	test.That(t, b, test.ShouldEqual, 7)

	p := plainOrFastParser{}
	m := RawMessage{}
	err := p.Parse(s, &m)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, m.Len, test.ShouldEqual, 7)
	test.That(t, len(m.Data), test.ShouldEqual, 7)
}

func TestStandardCandump2Analyzer(t *testing.T) {
	s := "2024-10-09-19:57:34.731,7,126720,3,255,8,20,11,e5,98,10,17,04,04"
	p := FindParser(s)
	test.That(t, p, test.ShouldNotBeNil)

	m := RawMessage{}
	err := p.Parse(s, &m)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, m.PGN, test.ShouldEqual, 126720)
	test.That(t, p.Name(), test.ShouldEqual, "PLAIN_OR_FAST")
}

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
