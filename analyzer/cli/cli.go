// Package cli provides a CLI for analyzing NMEA 2000 PGN messages
package cli

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

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"

	"github.com/erh/gonmea/analyzer"
	"github.com/erh/gonmea/common"
)

// A CLI lets a user run the analyzer in a CLI environment.
type CLI struct {
	ana    analyzer.Analyzer
	inFile *os.File
	config *cliConfig

	sep           string
	closingBraces string // } and ] chars to close sentence in JSON mode, otherwise empty string
	pb            printBuffer
}

type cliConfig struct {
	analyzer.Config

	ShowRaw       bool
	ShowData      bool
	ShowBytes     bool
	ShowJSON      bool
	ShowJSONEmpty bool
	ShowJSONValue bool
	ShowVersion   bool
	showSI        bool
	ShowGeo       geoFormat
	OnlyPgn       int64
	OnlySrc       int64
	OnlyDst       int64
}

func newConfig(
	logger logging.Logger,
) *cliConfig {
	base := analyzer.NewConfig(logger)
	return &cliConfig{
		Config:        *base,
		ShowRaw:       false,
		ShowData:      false,
		ShowBytes:     false,
		ShowJSON:      false,
		ShowJSONEmpty: false,
		ShowJSONValue: false,
		ShowVersion:   true,
		showSI:        false, // Output everything in strict SI units
		ShowGeo:       geoFormatDD,
		OnlyPgn:       int64(0),
		OnlySrc:       int64(-1),
		OnlyDst:       int64(-1),
	}
}

// analyzerImpl is shared between cli and analyzer until a better way is found.
type analyzerImpl interface {
	State() *analyzer.AnalyzerState

	SetCurrentFieldMetadata(
		fieldName string,
		data []byte,
		startBit int,
		numBits int,
	)
	ExtractNumberNotEmpty(
		field *analyzer.PGNField,
		data []byte,
		startBit int,
		numBits int,
		value *int64,
		maxValue *int64,
	) (bool, int64)
}

func New(args []string) (*CLI, error) {
	conf, inFile, err := parseCLIArgs(args)
	if err != nil {
		return nil, err
	}
	ana, err := analyzer.NewAnalyzer(&conf.Config)
	if err != nil {
		return nil, err
	}

	return &CLI{
		ana:    ana,
		inFile: inFile,
		config: conf,
		sep:    " ",
	}, nil
}

// parseCLIArgs parses the args of a CLI program into a cliConfig.
func parseCLIArgs(args []string) (*cliConfig, *os.File, error) {
	progNameAsExeced := args[0]

	conf := newConfig(common.NewLogger(os.Stderr))

	logLevel := zapcore.InfoLevel
	inFile := os.Stdin
	for argIdx := 1; argIdx < len(args); argIdx++ {
		arg := args[argIdx]
		hasNext := argIdx < len(args)-1

		//nolint:gocritic
		if strings.EqualFold(arg, "-raw") {
			conf.ShowRaw = true
		} else if strings.EqualFold(arg, "-debug") {
			conf.ShowJSONEmpty = true
			conf.ShowBytes = true
		} else if strings.EqualFold(arg, "-d") {
			logging.GlobalLogLevel.SetLevel(zapcore.DebugLevel)
			logLevel = zapcore.DebugLevel
		} else if strings.EqualFold(arg, "-q") {
			logging.GlobalLogLevel.SetLevel(zapcore.ErrorLevel)
			logLevel = zap.ErrorLevel
		} else if hasNext && strings.EqualFold(arg, "-geo") {
			nextArg := args[argIdx+1]
			if strings.EqualFold(nextArg, "dd") {
				conf.ShowGeo = geoFormatDD
			} else if strings.EqualFold(nextArg, "dm") {
				conf.ShowGeo = geoFormatDM
			} else if strings.EqualFold(nextArg, "dms") {
				conf.ShowGeo = geoFormatDMS
			} else {
				return nil, nil, cliUsage(progNameAsExeced, nextArg, os.Stdout)
			}
			argIdx++
		} else if strings.EqualFold(arg, "-si") {
			conf.showSI = true
		} else if strings.EqualFold(arg, "-nosi") {
			conf.showSI = false
		} else if strings.EqualFold(arg, "-json") {
			conf.ShowJSON = true
		} else if strings.EqualFold(arg, "-empty") {
			conf.ShowJSONEmpty = true
			conf.ShowJSON = true
		} else if strings.EqualFold(arg, "-nv") {
			conf.ShowJSONValue = true
			conf.ShowJSON = true
		} else if strings.EqualFold(arg, "-data") {
			conf.ShowData = true
		} else if hasNext && strings.EqualFold(arg, "-fixtime") {
			nextArg := args[argIdx+1]
			common.UseFixedTimestamp.Store(true)
			if !strings.Contains(nextArg, "n2kd") {
				conf.ShowVersion = false
			}
			argIdx++
		} else if hasNext && strings.EqualFold(arg, "-src") {
			nextArg := args[argIdx+1]
			//nolint:errcheck
			conf.OnlySrc, _ = strconv.ParseInt(nextArg, 10, 64)
			argIdx++
		} else if hasNext && strings.EqualFold(arg, "-dst") {
			nextArg := args[argIdx+1]
			//nolint:errcheck
			conf.OnlyDst, _ = strconv.ParseInt(nextArg, 10, 64)
			argIdx++
		} else if hasNext && strings.EqualFold(arg, "-file") {
			nextArg := args[argIdx+1]
			var err error
			//nolint:gosec
			inFile, err = os.OpenFile(nextArg, os.O_RDONLY, 0)
			if err != nil {
				return nil, nil, fmt.Errorf("Cannot open file %s", nextArg)
			}
			argIdx++
		} else if hasNext && strings.EqualFold(arg, "-format") {
			conf.DesiredFormat = args[argIdx+1]
			argIdx++
		} else {
			//nolint:errcheck
			conf.OnlyPgn, _ = strconv.ParseInt(arg, 10, 64)
			if conf.OnlyPgn > 0 {
				conf.Logger.Infof("Only logging PGN %d", conf.OnlyPgn)
			} else {
				return nil, nil, cliUsage(progNameAsExeced, arg, os.Stdout)
			}
		}
	}

	zapConf := logging.NewZapLoggerConfig()
	zapConf.Level = zap.NewAtomicLevelAt(logLevel)
	zapConf.OutputPaths = []string{"stderr"}
	zapLogger, err := zapConf.Build(zap.WithClock(common.FixedClock{}))
	if err != nil {
		return nil, nil, err
	}
	conf.Logger = logging.FromZapCompatible(zapLogger.Sugar())

	if common.UseFixedTimestamp.Load() {
		conf.Logger.Info("Timestamp fixed")
	}

	return conf, inFile, nil
}

// Run performs analysis.
func (c *CLI) Run() error {
	reader := bufio.NewReader(c.inFile)
	for {
		msg, isPrefix, err := reader.ReadLine()
		if err != nil || isPrefix {
			return nil
		}
		rawMsg, hasMsg, err := c.ana.ProcessRawMessage(string(msg))
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if !hasMsg {
			continue
		}
		if err := c.printCanFormat(rawMsg, os.Stdout); err != nil {
			return err
		}
		c.printCanRaw(rawMsg)
	}
}

//nolint:lll
func cliUsage(progNameAsExeced, invalidArgName string, writer io.Writer) error {
	fmt.Fprintf(writer, "Unknown or invalid argument %s\n", invalidArgName)
	fmt.Fprintf(writer, "Usage: %s [[-raw] [-json [-empty] [-nv] [-camel | -upper-camel]] [-data] [-debug] [-d] [-q] [-si] [-geo {dd|dm|dms}] "+
		"-format <fmt> "+
		"[-src <src> | -dst <dst> | <pgn>]] ["+
		"-version\n",
		progNameAsExeced)
	fmt.Fprintf(writer, "     -json             Output in json format, for program consumption. Empty values are skipped\n")
	fmt.Fprintf(writer, "     -empty            Modified json format where empty values are shown as NULL\n")
	fmt.Fprintf(writer, "     -nv               Modified json format where lookup values are shown as name, value pair\n")
	fmt.Fprintf(writer, "     -d                Print logging from level ERROR, INFO and DEBUG\n")
	fmt.Fprintf(writer, "     -q                Print logging from level ERROR\n")
	fmt.Fprintf(writer, "     -si               Show values in strict SI units: degrees Kelvin, rotation in radians/sec, etc.\n")
	fmt.Fprintf(writer, "     -geo dd           Print geographic format in dd.dddddd format\n")
	fmt.Fprintf(writer, "     -geo dm           Print geographic format in dd.mm.mmm format\n")
	fmt.Fprintf(writer, "     -geo dms          Print geographic format in dd.mm.sss format\n")
	fmt.Fprintf(writer, "     -format <fmt>     Select a particular format, either: ")
	for _, format := range common.AllParsers {
		fmt.Fprintf(writer, "%s, ", format.Name())
	}
	fmt.Fprintf(writer, "\n")
	fmt.Fprintf(writer, "     -version          Print the version of the program and quit\n")
	fmt.Fprintf(writer, "\nThe following options are used to debug the analyzer:\n")
	fmt.Fprintf(writer, "     -raw              Print the PGN in a format suitable to be fed to analyzer again (in standard raw format)\n")
	fmt.Fprintf(writer, "     -data             Print the PGN three times: in hex, ascii and analyzed\n")
	fmt.Fprintf(writer, "     -debug            Print raw value per field\n")
	fmt.Fprintf(writer, "     -fixtime str      Print str as timestamp in logging\n")
	fmt.Fprintf(writer, "\n")
	return &common.ExitError{Code: 1}
}

func (c *CLI) printCanFormat(
	msg *common.RawMessage,
	writer io.Writer,
) error {
	if c.config.OnlySrc >= 0 && c.config.OnlySrc != int64(msg.Src) {
		return nil
	}
	if c.config.OnlyDst >= 0 && c.config.OnlyDst != int64(msg.Dst) {
		return nil
	}
	if c.config.OnlyPgn > 0 && c.config.OnlyPgn != int64(msg.PGN) {
		return nil
	}

	impl := c.ana.(analyzerImpl)
	state := impl.State()

	pgn, _ := analyzer.SearchForPgn(msg.PGN)
	if state.MultiPackets == common.MultiPacketsSeparate && pgn == nil {
		var err error
		pgn, err = analyzer.SearchForUnknownPgn(msg.PGN, c.config.Logger)
		if err != nil {
			return err
		}
	}
	if state.MultiPackets == common.MultiPacketsCoalesced ||
		pgn == nil ||
		pgn.PacketType != analyzer.PacketTypeFast ||
		len(msg.Data) > 8 {
		// No reassembly needed
		return c.printPgn(msg, msg.Data[:msg.Len], writer)
	}

	// Fast packet requires re-asssembly
	// We only get here if we know for sure that the PGN is fast-packet
	// Possibly it is of unknown length when the PGN is unknown.

	var buffer int
	var p *analyzer.Packet
	for buffer = 0; buffer < analyzer.ReassemblyBufferSize; buffer++ {
		p = &state.ReassemblyBuffer[buffer]

		if p.Used && p.PGN == int(msg.PGN) && p.Src == int(msg.Src) {
			// Found existing slot
			break
		}
	}
	if buffer == analyzer.ReassemblyBufferSize {
		// Find a free slot
		for buffer = 0; buffer < analyzer.ReassemblyBufferSize; buffer++ {
			p = &state.ReassemblyBuffer[buffer]
			if !p.Used {
				break
			}
		}
		if buffer == analyzer.ReassemblyBufferSize {
			c.config.Logger.Errorf("Out of reassembly buffers; ignoring PGN %d", msg.PGN)
			return nil
		}
		p.Used = true
		p.Src = int(msg.Src)
		p.PGN = int(msg.PGN)
		p.Frames = 0
	}

	{
		// YDWG can receive frames out of order, so handle this.
		seq := uint8(msg.Data[0]&0xe0) >> 5
		frame := uint8(msg.Data[0] & 0x1f)

		idx := uint32(0)
		frameLen := common.FastPacketBucket0Size
		msgIdx := common.FastPacketBucket0Offset

		if frame != 0 {
			idx = common.FastPacketBucket0Size + uint32(frame-1)*common.FastPacketBucketNSize
			frameLen = common.FastPacketBucketNSize
			msgIdx = common.FastPacketBucketNOffset
		}

		if (p.Frames & (1 << frame)) != 0 {
			c.config.Logger.Errorf("Received incomplete fast packet PGN %d from source %d", msg.PGN, msg.Src)
			p.Frames = 0
		}

		if frame == 0 && p.Frames == 0 {
			p.Size = int(msg.Data[1])
			p.AllFrames = (1 << (1 + (p.Size / 7))) - 1
		}

		if len(msg.Data[msgIdx:]) < frameLen {
			return fmt.Errorf("frame (len=%d) smaller than expected (len=%d)", len(msg.Data[msgIdx:]), frameLen)
		}
		copy(p.Data[idx:], msg.Data[msgIdx:msgIdx+frameLen])
		p.Frames |= 1 << frame

		c.config.Logger.Debugf("Using buffer %d for reassembly of PGN %d: size %d frame %d sequence %d idx=%d frames=%x mask=%x",
			buffer,
			msg.PGN,
			p.Size,
			frame,
			seq,
			idx,
			p.Frames,
			p.AllFrames)
		if p.Frames == p.AllFrames {
			// Received all data
			if err := c.printPgn(msg, p.Data[:p.Size], writer); err != nil {
				return err
			}
			p.Used = false
			p.Frames = 0
		}
	}
	return nil
}

func (c *CLI) printPgn(
	msg *common.RawMessage,
	data []byte,
	writer io.Writer,
) error {
	if msg == nil {
		return nil
	}

	impl := c.ana.(analyzerImpl)
	pgn, err := analyzer.GetMatchingPgn(msg.PGN, data, c.config.Logger)
	if err != nil {
		return err
	}
	if pgn == nil {
		return fmt.Errorf("No PGN definition found for PGN %d", msg.PGN)
	}

	if c.config.ShowData {
		f := os.Stdout

		if c.config.ShowJSON {
			f = os.Stderr
		}

		fmt.Fprintf(f, "%s %d %3d %3d %6d %s: ", msg.Timestamp, msg.Prio, msg.Src, msg.Dst, msg.PGN, pgn.Description)
		for i := 0; i < len(data); i++ {
			fmt.Fprintf(f, " %2.02X", data[i])
		}
		fmt.Fprint(f, '\n')

		fmt.Fprintf(f, "%s %d %3d %3d %6d %s: ", msg.Timestamp, msg.Prio, msg.Src, msg.Dst, msg.PGN, pgn.Description)
		for i := 0; i < len(data); i++ {
			char := '.'
			if unicode.IsNumber(rune(data[i])) || unicode.IsLetter(rune(data[i])) {
				char = rune(data[i])
			}
			fmt.Fprintf(f, "  %c", char)
		}
		fmt.Fprint(f, '\n')
	}
	if c.config.ShowJSON {
		if pgn.CamelDescription != "" {
			c.pb.Printf("\"%s\":", pgn.CamelDescription)
		}
		c.pb.Printf("{\"timestamp\":\"%s\",\"prio\":%d,\"src\":%d,\"dst\":%d,\"pgn\":%d,\"description\":\"%s\"",
			msg.Timestamp,
			msg.Prio,
			msg.Src,
			msg.Dst,
			msg.PGN,
			pgn.Description)
		c.closingBraces = "}"
		c.sep = ",\"fields\":{"
	} else {
		c.pb.Printf("%s %d %3d %3d %6d %s:", msg.Timestamp, msg.Prio, msg.Src, msg.Dst, msg.PGN, pgn.Description)
		c.sep = " "
	}

	c.config.Logger.Debugf("FieldCount=%d RepeatingStart1=%d", pgn.FieldCount, pgn.RepeatingStart1)

	state := impl.State()
	state.VariableFieldRepeat[0] = 255 // Can be overridden by '# of parameters'
	state.VariableFieldRepeat[1] = 0   // Can be overridden by '# of parameters'
	repetition := 0
	variableFields := int64(0)
	r := true

	startBit := 0
	variableFieldStart := 0
	variableFieldCount := 0
	for i := 0; (startBit >> 3) < len(data); i++ {
		field := &pgn.FieldList[i]

		if variableFields == 0 {
			repetition = 0
		}

		if pgn.RepeatingCount1 > 0 && field.Order == pgn.RepeatingStart1 && repetition == 0 {
			if c.config.ShowJSON {
				sep, err := c.getSep()
				if err != nil {
					return err
				}
				c.pb.Printf("%s\"list\":[{", sep)
				c.closingBraces += "]}"
				c.sep = ""
			}
			// Only now is state.VariableFieldRepeat set
			variableFields = int64(pgn.RepeatingCount1) * state.VariableFieldRepeat[0]
			variableFieldCount = int(pgn.RepeatingCount1)
			variableFieldStart = int(pgn.RepeatingStart1)
			repetition = 1
		}
		if pgn.RepeatingCount2 > 0 && field.Order == pgn.RepeatingStart2 && repetition == 0 {
			if c.config.ShowJSON {
				c.pb.Print("}],\"list2\":[{")
				c.sep = ""
			}
			// Only now is state.VariableFieldRepeat set
			variableFields = int64(pgn.RepeatingCount2) * state.VariableFieldRepeat[1]
			variableFieldCount = int(pgn.RepeatingCount2)
			variableFieldStart = int(pgn.RepeatingStart2)
			repetition = 1
		}

		if variableFields > 0 {
			if i+1 == variableFieldStart+variableFieldCount {
				i = variableFieldStart - 1
				field = &pgn.FieldList[i]
				repetition++
				if c.config.ShowJSON {
					c.pb.Print("},{")
					c.sep = ""
				}
			}
			c.config.Logger.Debugf("variableFields: repetition=%d field=%d variableFieldStart=%d variableFieldCount=%d remaining=%d",
				repetition,
				i+1,
				variableFieldStart,
				variableFieldCount,
				variableFields)
			variableFields--
		}

		if field.CamelName == "" && field.Name == "" {
			c.config.Logger.Debugf("PGN %d has unknown bytes at end: %d", msg.PGN, len(data)-(startBit>>3))
			break
		}

		fieldName := field.Name
		if field.CamelName != "" {
			fieldName = field.CamelName
		}
		if repetition >= 1 && !c.config.ShowJSON {
			if field.CamelName != "" {
				fieldName += "_"
			} else {
				fieldName += " "
			}
			fieldName = fmt.Sprintf("%s%d", fieldName, repetition)
		}

		var countBits int
		if ok, err := c.printField(field, fieldName, data, startBit, &countBits); err != nil {
			return err
		} else if !ok {
			r = false
			break
		}

		startBit += countBits
	}

	if c.config.ShowJSON {
		for i := len(c.closingBraces); i != 0; {
			i--
			c.pb.Printf("%c", c.closingBraces[i])
		}
	}
	c.pb.Print("\n")

	if r {
		c.pb.Write(writer)
		if variableFields > 0 && state.VariableFieldRepeat[0] < math.MaxUint8 {
			c.config.Logger.Errorf("PGN %d has %d missing fields in repeating set", msg.PGN, variableFields)
		}
	} else {
		if !c.config.ShowJSON {
			c.pb.Write(writer)
		}
		c.pb.Reset()
		c.config.Logger.Errorf("PGN %d analysis error", msg.PGN)
	}

	return nil
}

const maxBraces = 15

func (c *CLI) getSep() (string, error) {
	s := c.sep

	if c.config.ShowJSON {
		c.sep = ","
		if strings.Contains(s, "{") {
			if len(c.closingBraces) >= maxBraces-1 {
				return "", errors.New("too many braces")
			}
			c.closingBraces += "}"
		}
	} else {
		c.sep = ";"
	}

	return s, nil
}

func (c *CLI) printField(
	field *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	if fieldName == "" {
		if field.CamelName != "" {
			fieldName = field.CamelName
		} else {
			fieldName = field.Name
		}
	}

	resolution := field.Resolution
	if resolution == 0.0 {
		resolution = field.FT.Resolution
	}

	c.config.Logger.Debugf("PGN %d: printField(<%s>, \"%s\", ..., startBit=%d) resolution=%g",
		field.PGN.PGN,
		field.Name,
		fieldName,
		startBit,
		resolution)

	var bytes int
	if field.Size != 0 || field.FT != nil {
		if field.Size != 0 {
			*bits = int(field.Size)
		} else {
			*bits = int(field.FT.Size)
		}
		bytes = (*bits + 7) / 8
		bytes = common.Min(bytes, len(data)-startBit/8)
		*bits = common.Min(bytes*8, *bits)
	} else {
		*bits = 0
	}

	impl := c.ana.(analyzerImpl)
	state := impl.State()
	impl.SetCurrentFieldMetadata(field.Name, data, startBit, *bits)

	c.config.Logger.Debugf("PGN %d: printField <%s>, \"%s\": bits=%d proprietary=%t RefPgn=%d",
		field.PGN.PGN,
		field.Name,
		fieldName,
		*bits,
		field.Proprietary,
		state.RefPgn)

	if field.Proprietary {
		if (state.RefPgn >= 65280 && state.RefPgn <= 65535) ||
			(state.RefPgn >= 126720 && state.RefPgn <= 126975) ||
			(state.RefPgn >= 130816 && state.RefPgn <= 131071) {
			// proprietary, allow field
		} else {
			// standard PGN, skip field
			*bits = 0
			return true, nil
		}
	}

	var oldClosingBracesLen int
	if field.FT != nil && field.FT.PF != nil {
		location := c.pb.Location()
		oldSep := c.sep
		oldClosingBracesLen = len(c.closingBraces)
		location2 := 0

		if !field.FT.PFIsPrintVariable {
			sep, err := c.getSep()
			if err != nil {
				return false, err
			}
			if c.config.ShowJSON {
				c.pb.Printf("%s\"%s\":", sep, fieldName)
				c.sep = ","
				if c.config.ShowBytes || c.config.ShowJSONValue {
					location2 = c.pb.Location()
				}
			} else {
				c.pb.Printf("%s %s = ", sep, fieldName)
				c.sep = ";"
			}
		}
		location3 := c.pb.Location()
		c.config.Logger.Debugf(
			"PGN %d: printField <%s>, \"%s\": calling function for %s", field.PGN.PGN, field.Name, fieldName, field.FieldType)
		state.Skip = false
		var err error
		r, err := field.FT.PF(c, field, fieldName, data, startBit, bits)
		if err != nil {
			return false, err
		}
		// if match fails, r == false. If field is not printed, state.Skip == true
		c.config.Logger.Debugf("PGN %d: printField <%s>, \"%s\": result %t bits=%d", field.PGN.PGN, field.Name, fieldName, r, *bits)
		if r && !state.Skip {
			if location3 == c.pb.Location() && !c.config.ShowBytes {
				c.config.Logger.Errorf("PGN %d: field \"%s\" print routine did not print anything", field.PGN.PGN, field.Name)
				r = false
			} else if c.config.ShowBytes && !field.FT.PFIsPrintVariable {
				location3 = c.pb.Location()
				if c.pb.Chr(location3-1) == '}' {
					c.pb.Set(location3 - 1)
				}
				c.showBytesOrBits(data[startBit>>3:], startBit&7, *bits)
				if c.config.ShowJSON {
					c.pb.Print("}")
				}
			}
			if location2 != 0 {
				location3 = c.pb.Location()
				if c.pb.Chr(location3-1) == '}' {
					// Prepend {"value":
					c.pb.Insert(location2, "{\"value\":")
				}
			}
		}
		if !r || state.Skip {
			c.pb.Set(location)
			c.sep = oldSep
			c.closingBraces = c.closingBraces[:oldClosingBracesLen]
		}
		return r, nil
	}
	c.config.Logger.Errorf("PGN %d: no function found to print field '%s'", field.PGN.PGN, fieldName)
	return false, nil
}

func (c *CLI) showBytesOrBits(data []byte, startBit, bits int) {
	if c.config.ShowJSON {
		location := c.pb.Location()

		if location == 0 || c.pb.Chr(location-1) != '{' {
			c.pb.Print(",")
		}
		c.pb.Print("\"bytes\":\"")
	} else {
		c.pb.Print(" (bytes = \"")
	}
	remainingBits := bits
	s := ""
	for i := 0; i < (bits+7)>>3; i++ {
		byteData := data[i]

		if i == 0 && startBit != 0 {
			byteData >>= startBit // Shift off older bits
			if remainingBits+startBit < 8 {
				byteData &= ((1 << remainingBits) - 1)
			}
			byteData <<= startBit // Shift zeros back in
			remainingBits -= (8 - startBit)
		} else {
			if remainingBits < 8 {
				// only the lower remainingBits should be used
				byteData &= ((1 << remainingBits) - 1)
			}
			remainingBits -= 8
		}
		c.pb.Printf("%s%2.02X", s, byteData)
		s = " "
	}
	c.pb.Print("\"")

	var value int64
	var maxValue int64

	if startBit != 0 || ((bits & 7) != 0) {
		analyzer.ExtractNumber(nil, data, startBit, bits, &value, &maxValue, c.config.Logger)
		if c.config.ShowJSON {
			c.pb.Print(",\"bits\":\"")
		} else {
			c.pb.Print(", bits = \"")
		}

		for i := bits; i > 0; {
			i--
			byteData := (value >> (i >> 3)) & 0xff
			char := '0'
			if (byteData & (1 << (i & 7))) != 0 {
				char = '1'
			}
			c.pb.Printf("%c", char)
		}
		c.pb.Print("\"")
	}

	if !c.config.ShowJSON {
		c.pb.Print(")")
	}
}

func (c *CLI) PrintFieldVariable(
	_ *analyzer.PGNField,
	fieldName string,
	data []byte,
	startBit int,
	bits *int,
) (bool, error) {
	impl := c.ana.(analyzerImpl)
	refField := analyzer.GetField(uint32(impl.State().RefPgn), uint32(data[startBit/8-1]-1), c.config.Logger)
	if refField != nil {
		c.config.Logger.Debugf("Field %s: found variable field %d '%s'", fieldName, impl.State().RefPgn, refField.Name)
		r, err := c.printField(refField, fieldName, data, startBit, bits)
		if err != nil {
			return false, err
		}
		*bits = (*bits + 7) & ^0x07 // round to bytes
		return r, nil
	}

	c.config.Logger.Errorf("Field %s: cannot derive variable length for PGN %d field # %d", fieldName, impl.State().RefPgn, data[len(data)-1])
	*bits = 8 /* Gotta assume something */
	return false, nil
}

func (c *CLI) printCanRaw(msg *common.RawMessage) {
	if c.config.OnlySrc >= 0 && c.config.OnlySrc != int64(msg.Src) {
		return
	}
	if c.config.OnlyDst >= 0 && c.config.OnlyDst != int64(msg.Dst) {
		return
	}
	if c.config.OnlyPgn > 0 && c.config.OnlyPgn != int64(msg.PGN) {
		return
	}

	f := os.Stdout
	if c.config.ShowJSON {
		f = os.Stderr
	}

	if c.config.ShowRaw && (c.config.OnlyPgn != 0 || c.config.OnlyPgn == int64(msg.PGN)) {
		fmt.Fprintf(f, "%s,%d,%d,%d,%d,%d", msg.Timestamp, msg.Prio, msg.PGN, msg.Src, msg.Dst, msg.Len)
		for i := uint8(0); i < msg.Len; i++ {
			fmt.Fprintf(f, ",%02x", msg.Data[i])
		}
		fmt.Fprintf(f, "\n")
	}
}
