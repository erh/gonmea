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
		if ok, err := ana.printField(field, fieldName, data, startBit, &countBits); err != nil {
			return nil, err
		} else if !ok {
			panic(1)
			break
		}

		startBit += countBits
	}

	return nil, nil
}
