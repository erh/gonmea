package analyzer

import (
	"fmt"
	"strings"
	
	"github.com/erh/gonmea/common"
)

func ParseLine(s string, showJSON bool, logger *common.Logger) (*common.RawMessage, error) {
	
	format, _ := detectFormat(s, logger)
	if format == rawFormatGarminCSV1 || format == rawFormatGarminCSV2 {
		return nil, fmt.Errorf("header line")
	}
	return ParseLineWithFormat([]byte(s), format, showJSON, logger)
}

func ParseLineWithFormat(msg []byte, format rawFormat, showJSON bool, logger *common.Logger) (*common.RawMessage, error) {
	var m common.RawMessage

	var r int
	switch format {
		case rawFormatPlainOrFast:
		r = common.ParseRawFormatPlain(msg, &m, showJSON, logger)
		logger.Debug("plain_or_fast: plain r=%d\n", r)
		if r < 0 {
			r = common.ParseRawFormatFast(msg, &m, showJSON, logger)
			logger.Debug("plain_or_fast: fast r=%d\n", r)
		}
		
	case rawFormatPlain:
		r = common.ParseRawFormatPlain(msg, &m, showJSON, logger)
		if r >= 0 {
			break
		}
		// Else fall through to fast!
		fallthrough
		
	case rawFormatFast:
		r = common.ParseRawFormatFast(msg, &m, showJSON, logger)
		if r >= 0 && format == rawFormatPlain {
			logger.Info("Detected normal format with all frames on one line\n")
			format = rawFormatFast
		}
		
	case rawFormatAirmar:
		r = common.ParseRawFormatAirmar(msg, &m, showJSON, logger)
		
	case rawFormatChetco:
		r = common.ParseRawFormatChetco(msg, &m, showJSON, logger)
		
	case rawFormatGarminCSV1, rawFormatGarminCSV2:
		r = common.ParseRawFormatGarminCSV(msg, &m, showJSON, format == rawFormatGarminCSV2, logger)
		
	case rawFormatYDWG02:
		r = common.ParseRawFormatYDWG02(msg, &m, logger)
		
	case rawFormatNavLink2:
		r = common.ParseRawFormatNavLink2(msg, &m, logger)
		
	case rawFormatActisenseN2KASCII:
		r = common.ParseRawFormatActisenseN2KAscii(msg, &m, showJSON, logger)
		
	case rawFormatUnknown:
		fallthrough
	default:
		return nil, fmt.Errorf("Unknown message format")
	}
	
	if r == 0 {
		return &m, nil
	}

	return nil, fmt.Errorf("Unknown message error %d: '%s'", r, msg)
}


func detectFormat(msg string, logger *common.Logger) (rawFormat, multipackets) {
	if msg[0] == '$' && msg == "$PCDIN" {
		if logger != nil {
			logger.Info("Detected Chetco protocol with all data on one line\n")
		}
		return rawFormatChetco, multipacketsCoalesced
	}

	if msg == "Sequence #,Timestamp,PGN,Name,Manufacturer,Remote Address,Local Address,Priority,Single Frame,Size,packet\n" {
		if logger != nil {
			logger.Info("Detected Garmin CSV protocol with relative timestamps\n")
		}
		return rawFormatGarminCSV1, multipacketsCoalesced
	}

	if msg ==
		"Sequence #,Month_Day_Year_Hours_Minutes_Seconds_msTicks,PGN,Processed PGN,Name,Manufacturer,Remote Address,Local "+
			"Address,Priority,Single Frame,Size,packet\n" {
		if logger != nil {
			logger.Info("Detected Garmin CSV protocol with absolute timestamps\n")
		}
		return rawFormatGarminCSV2, multipacketsCoalesced
	}

	p := strings.Index(msg, " ")
	if p != -1 && (msg[p+1] == '-' || msg[p+2] == '-') {
		if logger != nil {
			logger.Info("Detected Airmar protocol with all data on one line\n")
		}
		return rawFormatAirmar, multipacketsCoalesced
	}

	{
		var a, b, c, d, f int
		var e rune
		r, _ := fmt.Sscanf(msg, "%d:%d:%d.%d %c %02X ", &a, &b, &c, &d, &e, &f)
		if r == 6 && (e == 'R' || e == 'T') {
			if logger != nil {
				logger.Info("Detected YDWG-02 protocol with one line per frame\n")
			}
			return rawFormatYDWG02, multipacketsSeparate
		}
	}

	{
		var a, b, c, d int
		var e float64
		var f string
		r, _ := fmt.Sscanf(msg, "!PDGY,%d,%d,%d,%d,%f,%s ", &a, &b, &c, &d, &e, &f)
		if r == 6 {
			if logger != nil {
				logger.Info("Detected Digital Yacht NavLink2 protocol with one line per frame\n")
			}
			return rawFormatNavLink2, multipacketsCoalesced
		}
	}

	{
		var a, b, c, d int
		r1, _ := fmt.Sscanf(msg, "A%d.%d %x %x ", &a, &b, &c, &d)
		r2, _ := fmt.Sscanf(msg, "A%d %x %x ", &a, &b, &c)
		if r1 == 4 || r2 == 3 {
			if logger != nil {
				logger.Info("Detected Actisense N2K Ascii protocol with all frames on one line\n")
			}
			return rawFormatActisenseN2KASCII, multipacketsCoalesced
		}
	}

	p = strings.Index(msg, ",")
	if p != -1 {
		// NOTE(erd): this is a hacky af departure from the c code where it
		// can somehow use sscanf to count the number of hexes with
		// sscanf(p, ",%*u,%*u,%*u,%*u,%d,%*x,%*x,%*x,%*x,%*x,%*x,%*x,%*x,%*x", &len);
		var a, b, c, d, e int
		var hexes [9]hexScanner
		r, _ := fmt.Sscanf(
			msg[p:],
			",%d,%d,%d,%d,%d,%x,%x,%x,%x,%x,%x,%x,%x,%x",
			&a, &b, &c, &d, &e, &hexes[0], &hexes[1], &hexes[2], &hexes[3], &hexes[4], &hexes[5], &hexes[6], &hexes[7], &hexes[8],
		)
		if r < 1 {
			return rawFormatUnknown, multipacketsCoalesced
		}
		var countHex int
		for _, h := range hexes {
			if h.isSet {
				countHex++
			}
		}
		if countHex > 8 {
			if logger != nil {
				logger.Info("Detected normal format with all frames on one line\n")
			}
			return rawFormatFast, multipacketsCoalesced
		}
		if logger != nil {
			logger.Info("Assuming normal format with one line per frame\n")
		}
		return rawFormatPlain, multipacketsSeparate
	}

	return rawFormatUnknown, multipacketsSeparate
}
