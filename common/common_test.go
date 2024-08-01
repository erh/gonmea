package common

import (
	"fmt"
	"testing"

	"go.viam.com/test"
)

func TestGetISO11783BitsFromCanID(t *testing.T) {
	data := [][]uint{
		{502267650, 7, 126720, 2, 255},
		{0x09F11203, 2, 127250, 3, 255},
		{0x1DEF1911, 7, 126720, 17, 25},
	}

	for _, d := range data {
		prio, pgn, src, dst := GetISO11783BitsFromCanID(d[0])
		test.That(t, prio, test.ShouldEqual, d[1])
		test.That(t, pgn, test.ShouldEqual, d[2])
		test.That(t, src, test.ShouldEqual, d[3])
		test.That(t, dst, test.ShouldEqual, d[4])

		id := GetCanIDFromISO11783Bits(prio, pgn, src, dst)
		test.That(t, fmt.Sprintf("%x", d[0]), test.ShouldEqual, fmt.Sprintf("%x", id))
	}

}
