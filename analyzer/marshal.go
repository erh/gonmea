package analyzer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/erh/gonmea/common"
)

// Derived from https://github.com/canboat/canboat (Apache License, Version 2.0)
// (C) 2009-2023, Kees Verruijt, Harlingen, The Netherlands.

// MarshalMessageToRaw marshals the given message into a raw message. This message is
// then suitable to be further marshaled into a PGN format.
func MarshalMessageToRaw(msg *common.Message) (*common.RawMessage, error) {
	ana, err := newOneOffAnalyzer()
	if err != nil {
		return nil, err
	}

	data, err := ana.(*analyzerImpl).marshalPGN(msg)
	if err != nil {
		return nil, err
	}

	if len(data) > math.MaxUint8 {
		return nil, errors.New("marshaled data too long")
	}

	return &common.RawMessage{
		Timestamp: msg.Timestamp,
		Prio:      uint8(msg.Priority),
		PGN:       uint32(msg.PGN),
		Dst:       uint8(msg.Dst),
		Src:       uint8(msg.Src),
		Len:       uint8(len(data)),
		Data:      data,
	}, nil
}

type bitWriter struct {
	dirty       byte
	dirtyBitPos int
	data        []byte
}

func (bw *bitWriter) writeBitRepeat(one bool, nBits int) {
	bitVal := 0
	if one {
		bitVal = 1
	}
	for bitPos := 0; bitPos < nBits; bitPos++ {
		bw.dirty |= byte(bitVal) << bw.dirtyBitPos
		bw.dirtyBitPos++

		if bw.dirtyBitPos == 8 {
			bw.flush()
		}
	}
}

func (bw *bitWriter) writeIntBits(val int64, nBits int) {
	for bitPos := 0; bitPos < nBits; bitPos++ {
		maskedBit := val & (1 << bitPos)
		bit := maskedBit >> bitPos
		bw.dirty |= byte(bit << bw.dirtyBitPos)
		bw.dirtyBitPos++

		if bw.dirtyBitPos == 8 {
			bw.flush()
		}
	}
}

func (bw *bitWriter) writeBytesAsBits(data []byte, nBits int) {
	for dataBitPos := 0; dataBitPos < nBits && dataBitPos/8 < len(data); dataBitPos++ {
		dataIdx := dataBitPos / 8
		bitPos := dataBitPos % 8
		val := data[dataIdx]
		maskedBit := val & (1 << bitPos)
		bit := maskedBit >> bitPos
		bw.dirty |= bit << bw.dirtyBitPos
		bw.dirtyBitPos++

		if bw.dirtyBitPos == 8 {
			bw.flush()
		}
	}
}

func (bw *bitWriter) flush() {
	if bw.dirtyBitPos != 0 {
		bw.data = append(bw.data, bw.dirty)
		bw.dirty = 0
		bw.dirtyBitPos = 0
	}
}

func (bw *bitWriter) length() int {
	return len(bw.data)*8 + bw.dirtyBitPos
}

func (ana *analyzerImpl) marshalPGN(msg *common.Message) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("expected message")
	}
	pgn, err := GetMatchingPgnWithFields(uint32(msg.PGN), msg.Fields, ana.Logger)
	if err != nil {
		return nil, err
	}
	if pgn == nil {
		return nil, fmt.Errorf("no PGN definition found for PGN %d", msg.PGN)
	}

	ana.Logger.Debugf("FieldCount=%d RepeatingStart1=%d", pgn.FieldCount, pgn.RepeatingStart1)

	repetition := 0
	variableFields := int64(0)

	writer := &bitWriter{}
	variableFieldStart := 0
	variableFieldCount := 0
	var repeatingListName string
	var fieldList []interface{}
	for i := 0; i < int(pgn.FieldCount) || variableFields != 0; i++ {
		field := &pgn.FieldList[i]

		if variableFields == 0 {
			repetition = 0
		}

		if pgn.RepeatingCount1 > 0 && field.Order == pgn.RepeatingStart1 && repetition == 0 {
			fieldList = nil
			repeatingListName = "list"
			if list, ok := msg.Fields[repeatingListName]; ok {
				fieldList, ok = list.([]interface{})
				if !ok {
					return nil, fmt.Errorf("field list is invalid %v", msg.Fields[repeatingListName])
				}
			}
			variableFields = int64(pgn.RepeatingCount1) * int64(len(fieldList))
			variableFieldCount = int(pgn.RepeatingCount1)
			variableFieldStart = int(pgn.RepeatingStart1)
			repetition = 1
		}
		if pgn.RepeatingCount2 > 0 && field.Order == pgn.RepeatingStart2 && repetition == 0 {
			fieldList = nil
			repeatingListName = "list2"
			if list, ok := msg.Fields[repeatingListName]; ok {
				fieldList, ok = list.([]interface{})
				if !ok {
					return nil, fmt.Errorf("field list is invalid %v", msg.Fields[repeatingListName])
				}
			}
			variableFields = int64(pgn.RepeatingCount2) * int64(len(fieldList))
			variableFieldCount = int(pgn.RepeatingCount2)
			variableFieldStart = int(pgn.RepeatingStart2)
			repetition = 1
		}

		if variableFields > 0 {
			if i+1 == variableFieldStart+variableFieldCount {
				i = variableFieldStart - 1
				field = &pgn.FieldList[i]
				repetition++
			}
			ana.Logger.Debugf("variableFields: repetition=%d field=%d variableFieldStart=%d variableFieldCount=%d remaining=%d",
				repetition,
				i+1,
				variableFieldStart,
				variableFieldCount,
				variableFields)
			variableFields--
		}

		var fieldValue interface{}
		if repetition == 0 {
			fieldValue = msg.Fields[field.Name]
		} else {
			if len(fieldList) == 0 {
				i += variableFieldCount
				continue
			}
			listIdx := repetition - 1
			if listIdx >= len(fieldList) {
				return nil, fmt.Errorf("field list is too small %v", fieldList)
			}
			fieldObj, ok := fieldList[listIdx].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("field list value is invalid %v", fieldList[listIdx])
			}

			fieldValue = fieldObj[field.Name]
		}

		var numBytes int
		var numBits int
		if field.Size != 0 || field.FT != nil {
			if field.Size != 0 {
				numBits = int(field.Size)
			} else {
				numBits = int(field.FT.Size)
			}
			numBytes = (numBits + 7) / 8
			numBits = common.Min(numBytes*8, numBits)
		} else {
			numBits = 0
		}

		if err := ana.marshalField(field, fieldValue, numBits, writer); err != nil {
			return nil, err
		}
	}
	writer.flush()
	return writer.data, nil
}

func (ana *analyzerImpl) marshalField(
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	if field.Proprietary {
		if (ana.state.RefPgn >= 65280 && ana.state.RefPgn <= 65535) ||
			(ana.state.RefPgn >= 126720 && ana.state.RefPgn <= 126975) ||
			(ana.state.RefPgn >= 130816 && ana.state.RefPgn <= 131071) {
			// Proprietary, allow field
		} else {
			// standard PGN, skip field
			return nil
		}
	}

	if value == nil {
		if field.HasSign {
			ana.Logger.Debugf("missing field '%s'; writing max signed value", field.Name)
			// write max signed value
			writer.writeBitRepeat(true, numBits-1)
			writer.writeBitRepeat(false, 1)
		} else {
			ana.Logger.Debugf("missing field '%s; writing ones=%t", field.Name, field.MissingValueIsOne)
			writer.writeBitRepeat(field.MissingValueIsOne != nil && *field.MissingValueIsOne, numBits)
		}
		return nil
	}

	if field.FT != nil && field.FT.MF != nil {
		ana.Logger.Debugf(
			"PGN %d: marshalField <%s>: calling function for %s", field.PGN.PGN, field.Name, field.FieldType)
		ana.state.Skip = false
		return field.FT.MF(ana, field, value, numBits, writer)
	}
	return fmt.Errorf("PGN %d: no function found to convert field '%s'", field.PGN.PGN, field.Name)
}

func marshalFieldNumber(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	switch v := value.(type) {
	case int:
		writer.writeIntBits(int64(v), numBits)
		return nil
	case float64:
		// rounding seems to help with floating point imprecision but may not be the best
		// solution.
		toWrite := int64(math.Round((v - field.UnitOffset) / field.Resolution))
		if field.Offset != 0 /* J1939 Excess-K notation */ {
			toWrite -= int64(field.Offset)
		}
		writer.writeIntBits(toWrite, numBits)
		return nil
	default:
		return fmt.Errorf("expected int or float64 but got %T (%v)", v, v)
	}
}

// Note(UNTESTED): See README.md.
func marshalFieldFloat(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueFloat, ok := value.(float64)
	if !ok {
		return wrongTypeError("float64", value, field)
	}

	writer.flush()
	writer.data = binary.BigEndian.AppendUint32(writer.data, math.Float32bits(float32(valueFloat)))
	return nil
}

// Note(UNTESTED): See README.md.
func marshalFieldDecimal(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueFloat, ok := value.(float64)
	if !ok {
		return wrongTypeError("float64", value, field)
	}

	writer.flush()
	writer.data = binary.BigEndian.AppendUint64(writer.data, math.Float64bits(valueFloat))
	return nil
}

func marshalFieldLookup(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	switch v := value.(type) {
	case int:
		writer.writeIntBits(int64(v), numBits)
		return nil
	case string:
		valueStr, ok := value.(string)
		if !ok {
			return wrongTypeError("string", value, field)
		}

		var ret int
		if field.Lookup.LookupType != LookupTypeNone {
			if field.Lookup.LookupType == LookupTypePair || field.Lookup.LookupType == LookupTypeFieldType {
				ret = field.Lookup.FunctionPairReverse(valueStr)
			} else if field.Lookup.LookupType == LookupTypeTriplet {
				_, ret = field.Lookup.FunctionTripletReverse(valueStr)
			}
			// BIT is handled in marshalFieldBitLookup
		}

		writer.writeIntBits(int64(ret), numBits)
		return nil
	default:
		return fmt.Errorf("expected string or int (raw) but got %T", v)
	}
}

func marshalFieldBitLookup(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueIfcs, ok := value.([]interface{})
	if !ok {
		return wrongTypeError("[]interface{}", value, field)
	}

	for _, valueIfc := range valueIfcs {
		switch v := valueIfc.(type) {
		case int:
			writer.writeBitRepeat(false, 1)
		case string:
			writer.writeBitRepeat(true, 1)
		default:
			return fmt.Errorf("expected int or string but got %T", v)
		}
	}
	return nil
}

func marshalFieldBinary(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueBin, ok := value.([]uint8)
	if !ok {
		return wrongTypeError("[]uint8", value, field)
	}

	writer.writeBytesAsBits(valueBin, numBits)
	return nil
}

func marshalFieldReserved(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	return marshalFieldBinary(ana, field, value, numBits, writer)
}

// Note(UNTESTED): See README.md.
func marshalFieldSpare(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	writer.writeBitRepeat(false, numBits)
	return nil
}

// This is only a different marshaler than marshalFieldNumber so the JSON can contain a string value.
func marshalFieldMMSI(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueInt, ok := value.(int)
	if !ok {
		return wrongTypeError("int", value, field)
	}

	writer.writeIntBits(int64(valueInt), numBits)
	return nil
}

// Note(UNTESTED): See README.md.
func marshalFieldKeyValue(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	panic("unimplemented; have yet to see this; not worth implementing until there is real data")
}

func marshalFieldLatLon(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueFloat, ok := value.(float64)
	if !ok {
		return wrongTypeError("float64", value, field)
	}

	// rounding seems to help with floating point imprecision but may not be the best
	// solution.
	writer.writeIntBits(int64(math.Round(valueFloat/field.Resolution)), numBits)
	return nil
}

func marshalFieldDate(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueTime, ok := value.(time.Time)
	if !ok {
		return wrongTypeError("time.Time", value, field)
	}

	days := uint16(valueTime.Unix() / 86400)
	writer.data = binary.LittleEndian.AppendUint16(writer.data, days)
	return nil
}

// assumed aligned.
func marshalString(str string, writer *bitWriter, numBits int) {
	writer.data = append(writer.data, []byte(str)...)
	remBits := numBits - len(str)*8
	if remBits > 0 {
		writer.writeBitRepeat(true, remBits)
	}
}

/**
 * Fixed length string where the length is defined by the field definition.
 */
func marshalFieldStringFix(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueStr, ok := value.(string)
	if !ok {
		return wrongTypeError("string", value, field)
	}

	marshalString(valueStr, writer, numBits)
	return nil
}

// Note(UNTESTED): See README.md.
func marshalFieldStringLZ(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueStr, ok := value.(string)
	if !ok {
		return wrongTypeError("string", value, field)
	}

	writer.data = append(writer.data, byte(len(valueStr)))
	marshalString(valueStr, writer, len(valueStr)*8)
	return nil
}

func marshalFieldStringLAU(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueStr, ok := value.(string)
	if !ok {
		return wrongTypeError("string", value, field)
	}

	writer.data = append(writer.data, byte(len(valueStr)+2), 0x01) // len including this, control=1 (utf8)
	marshalString(valueStr, writer, len(valueStr)*8)
	return nil
}

func marshalFieldTime(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	numBits int,
	writer *bitWriter,
) error {
	valueDur, ok := value.(time.Duration)
	if !ok {
		return wrongTypeError("time.Duration", value, field)
	}

	positive := true
	if valueDur < 0 {
		valueDur = -valueDur
		positive = false
	}

	unitspersecond := int64(1)
	if field.Resolution < 1.0 {
		unitspersecond = int64(1.0 / field.Resolution)
	}

	seconds := int64(valueDur.Seconds()) * unitspersecond
	if field.Resolution >= 1.0 {
		seconds *= int64(field.Resolution)
	}
	if !positive {
		seconds *= -1
	}

	writer.writeIntBits(seconds, numBits)
	return nil
}

func marshalFieldVariable(
	ana *analyzerImpl,
	field *PGNField,
	value interface{},
	_ int,
	writer *bitWriter,
) error {
	valueFieldVar, ok := value.(common.FieldVariable)
	if !ok {
		return wrongTypeError("common.FieldVariable", value, field)
	}

	refField := GetField(valueFieldVar.PGN, valueFieldVar.Index-1, ana.Logger)
	if refField != nil {
		ana.Logger.Debugf("found variable field %d '%s'", valueFieldVar.PGN, refField.Name)

		var numBytes int
		var newNumBits int
		if refField.Size != 0 || refField.FT != nil {
			if refField.Size != 0 {
				newNumBits = int(refField.Size)
			} else {
				newNumBits = int(refField.FT.Size)
			}
			numBytes = (newNumBits + 7) / 8
			newNumBits = common.Min(numBytes*8, newNumBits)
		} else {
			newNumBits = 0
		}

		if err := ana.marshalField(refField, valueFieldVar.Value, newNumBits, writer); err != nil {
			return err
		}
		writer.flush() // seem to need this
		return nil
	}

	return fmt.Errorf("cannot derive variable length for PGN %d field # %d", valueFieldVar.PGN, valueFieldVar.Index)
}

func wrongTypeError(expected string, value interface{}, field *PGNField) error {
	return fmt.Errorf("expected value to be a %s but got a %T (%v) for %s", expected, value, value, field.Name)
}
