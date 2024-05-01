package analyzer

import (
	"fmt"
	
	"github.com/erh/gonmea/common"
)


func (ana *Analyzer) ConvertFields(msg *common.RawMessage) (map[string]interface{}, error) {
	data := msg.Data[:msg.Len]
	
	pgn, err := ana.getMatchingPgn(msg.PGN, data)
	if err != nil {
		return nil, err
	}

	if ana.multipackets != multipacketsCoalesced && pgn.packetType == packetTypeFast {
		return nil, fmt.Errorf("do i have to re-assumble????  pgn %v", msg.PGN)
	}
	
	variableFields := int64(0)
	repetition := 0
	
	startBit := 0
	
	for i := 0; (startBit >> 3) < len(data); i++ {
		//fmt.Printf("i: %v startBit: %v len: %v\n", i, startBit, len(data))
		field := &pgn.fieldList[i]

		if variableFields == 0 {
			repetition = 0
		}

		if pgn.repeatingCount1 > 0 && field.order == pgn.repeatingStart1 && repetition == 0 {
			return nil, fmt.Errorf("can't handle repeatingCount1")
		}
		if pgn.repeatingCount2 > 0 && field.order == pgn.repeatingStart2 && repetition == 0 {
			return nil, fmt.Errorf("can't handle repeatingCount2")
		}

		if variableFields > 0 {
			return nil, fmt.Errorf("can't handle variableFields")
		}

		if field.camelName == "" && field.name == "" {
			return nil, fmt.Errorf("no name for field for pgn: %v field: %v", msg.PGN, field)
		}

		fieldName := field.name
		if field.name == "" || field.camelName != "" {
			fieldName = field.camelName
		}

		fmt.Printf("%s\n", fieldName)
		var countBits int
		val, err := ana.convertFieldValue(field, data, startBit, &countBits)
		if err != nil {
			return nil, err
		}
		startBit += countBits
		
		data[fieldName] = val
	}

	return data, nil
}

func (ana *Analyzer) convertFieldValue(
	field *pgnField,
	data []byte,
	startBit int,
	bits *int,
) (interface{}, error) {

	resolution := field.resolution
	if resolution == 0.0 {
		resolution = field.ft.resolution
	}

	ana.Logger.Debug("PGN %d: printField(<%s>, \"%s\", ..., startBit=%d) resolution=%g\n",
		field.pgn.pgn,
		field.name,
		fieldName,
		startBit,
		resolution)

	var bytes int
	if field.size != 0 || field.ft != nil {
		if field.size != 0 {
			*bits = int(field.size)
		} else {
			*bits = int(field.ft.size)
		}
		bytes = (*bits + 7) / 8
		bytes = common.Min(bytes, len(data)-startBit/8)
		*bits = common.Min(bytes*8, *bits)
	} else {
		*bits = 0
	}

	// TODO: i think this is ok, but need to clean up globals
	ana.fillGlobalsBasedOnFieldName(field.name, data, startBit, *bits)

	ana.Logger.Debug("PGN %d: printField <%s>, \"%s\": bits=%d proprietary=%t refPgn=%d\n",
		field.pgn.pgn,
		field.name,
		fieldName,
		*bits,
		field.proprietary,
		ana.refPgn)

	if field.proprietary {
		if (ana.refPgn >= 65280 && ana.refPgn <= 65535) ||
			(ana.refPgn >= 126720 && ana.refPgn <= 126975) ||
			(ana.refPgn >= 130816 && ana.refPgn <= 131071) {
			// proprietary, allow field
		} else {
			// standard PGN, skip field
			*bits = 0
			return nil, nil // TODO: I guess this just means it's a blank field??
		}
	}

	if field.ft != nil && field.ft.pf != nil {
		r, err := field.ft.pf(ana, field, fieldName, data, startBit, bits)
	}
	//nolint:errcheck
	ana.Logger.Error("PGN %d: no function found to print field '%s'\n", field.pgn.pgn, fieldName)
	return false, nil
}
