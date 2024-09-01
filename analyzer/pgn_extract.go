package analyzer

import (
	"math"

	"go.viam.com/rdk/logging"

	"github.com/erh/gonmea/common"
)

// Originally from https://github.com/canboat/canboat (Apache License, Version 2.0)
// (C) 2009-2023, Kees Verruijt, Harlingen, The Netherlands.

// This file is part of CANboat.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

func AdjustDataLenStart(data []byte, startBit *int) ([]byte, bool) {
	bytes := *startBit >> 3

	if bytes < len(data) {
		*startBit &= 7
		return data[bytes:], true
	}

	return nil, false
}

/*
 * Find a field by Order. This will only work for a field that
 * is at a predefined bit offset, so no variable fields before
 * it.
 *
 * It is currently only used for LOOKUP_TYPE_TRIPLET.
 */
func GetFieldOffsetByOrder(pgn *PGNInfo, order int) int {
	bitOffset := 0

	for i := 0; i < order; i++ {
		field := &pgn.FieldList[i]

		if i+1 == order {
			return bitOffset
		}
		bitOffset += int(field.Size)
	}
	return 0
}

func ExtractNumberByOrder(pgn *PGNInfo, order int, data []byte, value *int64, logger logging.Logger) bool {
	field := &pgn.FieldList[order-1]
	bitOffset := GetFieldOffsetByOrder(pgn, order)

	var startBit int
	var maxValue int64

	startBit = bitOffset & 7
	data = data[bitOffset>>3:]

	return ExtractNumber(field, data, startBit, int(field.Size), value, &maxValue, logger)
}

func ExtractNumber(
	field *PGNField,
	data []byte,
	startBit int,
	numBits int,
	value *int64,
	maxValue *int64,
	logger logging.Logger,
) bool {
	var hasSign bool
	if field == nil {
		hasSign = false
	} else {
		hasSign = field.HasSign
	}
	var name string
	if field == nil {
		name = "<bits>"
	} else {
		name = field.Name
	}

	bitsRemaining := numBits
	magnitude := 0
	var bitsInThisByte int
	var bitMask uint64
	var allOnes uint64
	var valueInThisByte uint64
	var maxv uint64

	logger.Debugf("ExtractNumber <%s> startBit=%d bits=%d", name, startBit, numBits)

	data, adjusted := AdjustDataLenStart(data, &startBit)
	if !adjusted {
		return false
	}

	firstBit := startBit
	*value = 0
	maxv = 0

	for bitsRemaining > 0 && len(data) > 0 {
		bitsInThisByte = common.Min(8-firstBit, bitsRemaining)
		allOnes = ((uint64(1)) << bitsInThisByte) - 1

		// How are bits ordered in bytes for bit fields? There are two ways, first field at LSB or first
		// field as MSB.
		// Experimentation, using the 129026 PGN, has shown that the most likely candidate is LSB.
		bitMask = allOnes << firstBit
		valueInThisByte = (uint64(data[0]) & bitMask) >> firstBit

		*value |= int64(valueInThisByte << magnitude)
		maxv |= allOnes << magnitude

		magnitude += bitsInThisByte
		bitsRemaining -= bitsInThisByte
		firstBit += bitsInThisByte
		if firstBit >= 8 {
			firstBit -= 8
			data = data[1:]
		}
	}
	if bitsRemaining > 0 {
		logger.Debugf("Insufficient length in PGN to fill field '%s'", name)
		return false
	}

	if hasSign {
		maxv >>= 1

		if field != nil && field.Offset != 0 /* J1939 Excess-K notation */ {
			*value += int64(field.Offset)
			maxv += uint64(field.Offset)
		} else {
			negative := (*value & int64(((uint64(1)) << (numBits - 1)))) > 0

			if negative {
				/* Sign extend value for cases where bits < 64 */
				/* Assume we have bits = 16 and value = -2 then we do: */
				/* 0000.0000.0000.0000.0111.1111.1111.1101 value    */
				/* 0000.0000.0000.0000.0111.1111.1111.1111 maxvalue */
				/* 1111.1111.1111.1111.1000.0000.0000.0000 ~maxvalue */
				*value |= int64(^maxv)
			}
		}
	} else if field != nil && field.Offset != 0 /* J1939 Excess-K notation */ {
		*value += int64(field.Offset)
		maxv += uint64(field.Offset)
	}

	if maxv == math.MaxUint64 {
		*maxValue = math.MaxInt64
	} else {
		*maxValue = int64(maxv)
	}

	logger.Debugf("ExtractNumber <%s> startBit=%d bits=%d value=%d max=%d", name, startBit, numBits, *value, *maxValue)

	return true
}

func (ana *analyzerImpl) ExtractNumberNotEmpty(
	field *PGNField,
	data []byte,
	startBit int,
	numBits int,
	value *int64,
	maxValue *int64,
) (bool, int64) { // int is exceptionValue
	var reserved int64

	if !ExtractNumber(field, data, startBit, numBits, value, maxValue, ana.Logger) {
		return false, 0
	}

	//nolint:gocritic
	if *maxValue >= 7 {
		reserved = 2 /* dataFieldError and dataFieldUnknown */
	} else if *maxValue > 1 {
		reserved = 1 /* dataFieldUnknown */
	} else {
		reserved = 0
	}

	if field.PGN != nil && field.PGN.RepeatingField1 == field.Order {
		ana.Logger.Debugf("The first repeating fieldset repeats %d times", *value)
		ana.state.VariableFieldRepeat[0] = *value
	}

	if field.PGN != nil && field.PGN.RepeatingField2 == field.Order {
		ana.Logger.Debugf("The second repeating fieldset repeats %d times", *value)
		ana.state.VariableFieldRepeat[1] = *value
	}

	ana.state.PreviousFieldValue = *value

	if *value > *maxValue-reserved {
		return false, *value - *maxValue
	}

	return true, 0
}
