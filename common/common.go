package common

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
	"cmp"
	"fmt"
	"io"
	"strings"
	"time"
)

// FastPacket constants.
const (
	FastPacketIndex         = 0
	FastPacketSize          = 1
	FastPacketBucket0Size   = 6
	FastPacketBucketNSize   = 7
	FastPacketBucket0Offset = 2
	FastPacketBucketNOffset = 1
	FastPacketMaxIndex      = 0x1f
	FastPacketMaxSize       = FastPacketBucket0Size + FastPacketBucketNSize*FastPacketMaxIndex
)

/*
 * The 'converter' programs generate fake PGNs containing data that they generate
 * themselves or via proprietary non-PGN serial messages.
 * These need unique fake PGNs.
 */
const (
	CANBoatPGNStart = 0x40000
	CANBoatPGNEnd   = 0x401FF
	ActisenseBEM    = 0x40000 /* Actisense specific fake PGNs */
	IKnovertBEM     = 0x40100 /* iKonvert specific fake PGNs */
)

// Logger is for logging.
type Logger struct {
	level          LogLevel
	progName       string
	fixedTimestamp string
	writer         io.Writer
	isCLI          bool
}

func newLogger(writer io.Writer, isCLI bool) *Logger {
	return &Logger{
		level:  LogLevelInfo,
		writer: writer,
		isCLI:  isCLI,
	}
}

// NewLogger returns a new logger.
func NewLogger(writer io.Writer) *Logger {
	return newLogger(writer, false)
}

// NewLoggerForCLI returns a new logger for use by a CLI.
func NewLoggerForCLI(writer io.Writer) *Logger {
	return newLogger(writer, true)
}

// LogLevel represents a level to log at.
type LogLevel int

// All log levels.
const (
	LogLevelFatal LogLevel = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
)

// String returns the human readable LogLevel.
func (l LogLevel) String() string {
	switch l {
	case LogLevelFatal:
		return "FATAL"
	case LogLevelError:
		return "ERROR"
	case LogLevelInfo:
		return "INFO"
	case LogLevelDebug:
		return "DEBUG"
	default:
		return "UNKNOWN"
	}
}

// Now returns the current time.Time as seen by the logger.
func (l *Logger) Now() time.Time {
	if l.fixedTimestamp != "" {
		return time.UnixMilli(1672527600000) // 2023-01-01 00:00
	}

	return time.Now()
}

func (l *Logger) now() string {
	asOfNow := l.Now()

	if l.fixedTimestamp != "" {
		return l.fixedTimestamp
	}

	// Note: there are more fractional bits printed than the C version
	// but this shouldn't practically matter
	return asOfNow.UTC().Format(time.RFC3339Nano)
}

func (l *Logger) log(level LogLevel, format string, v ...any) {
	if level > l.level {
		return
	}

	fmt.Fprintf(l.writer, "%s %s ", level, l.now())
	if l.progName != "" {
		fmt.Fprintf(l.writer, "[%s] ", l.progName)
	}
	fmt.Fprintf(l.writer, format, v...)
}

// Info logs a message at the INFO level.
func (l *Logger) Info(format string, v ...any) {
	l.log(LogLevelInfo, format, v...)
}

// Debug logs a message at the DEBUG level.
func (l *Logger) Debug(format string, v ...any) {
	l.log(LogLevelDebug, format, v...)
}

// Error logs a message at the ERROR level. The returned
// error may be used to propagate upwards.
func (l *Logger) Error(format string, v ...any) error {
	l.log(LogLevelError, format, v...)
	err := fmt.Errorf(format, v...)
	if !l.isCLI {
		return err
	}
	return &ExitError{Code: 2, Cause: err}
}

// Abort logs a message at the FATAL level. The returned
// error may be used to propagate upwards and if running
// as a CLI, it may os.Exit.
func (l *Logger) Abort(format string, v ...any) error {
	l.log(LogLevelFatal, format, v...)
	err := fmt.Errorf(format, v...)
	if !l.isCLI {
		return err
	}
	return &ExitError{Code: 2, Cause: err}
}

// SetProgName sets the program name running this
// logger (used by CLI).
func (l *Logger) SetProgName(name string) {
	nameIdx := strings.LastIndex(name, "/")
	if nameIdx == -1 {
		nameIdx = strings.LastIndex(name, "\\")
	}
	if nameIdx == -1 {
		l.progName = name
	} else {
		l.progName = name[nameIdx+1:]
	}
}

// Min returns the min of x,y.
func Min[T cmp.Ordered](x, y T) T {
	if x < y {
		return x
	}
	return y
}

// Max returns the max of x,y.
func Max[T cmp.Ordered](x, y T) T {
	if x > y {
		return x
	}
	return y
}

// SetLogLevel sets the logger's log level.
func (l *Logger) SetLogLevel(level LogLevel) {
	l.level = Min(Max(level, LogLevelFatal), LogLevelDebug)
	l.Debug("Loglevel now %d\n", l.level)
}

// SetFixedTimestamp sets a fixed timestamp for logs.
func (l *Logger) SetFixedTimestamp(fixedStr string) {
	l.fixedTimestamp = fixedStr
	l.Info("Timestamp fixed\n")
}

// AllowPGNFastPacket returns if this PGN Fast is allowed.
func AllowPGNFastPacket(n uint32) bool {
	return (((n) >= 0x10000 && (n) < 0x1FFFF) || (n) >= CANBoatPGNStart)
}

// AllowPGNSingleFrame returns if this PGN can be in a single frame.
func AllowPGNSingleFrame(n uint32) bool {
	return ((n) < 0x10000 || (n) >= 0x1F000)
}

/*
 * Table 1 - Mapping of ISO 11783 into CAN's Arbitration and Control Fields
29 Bit Identifiers
CAN   ISO 11783 Bit Number
SOF     SOF*      1
ID 28   P 3       2
ID 27   P 2       3
ID 26   P 1       4
ID 23   R 1       5
ID 24   DP        6
ID 23   PF 8      7
ID 22   PF 7      8
ID 21   PF 6      9
ID 20   PF 5     10
ID 19   PF 4     11
ID 18   PF 3     12
SRR (r) SRR*     13
IDE (r) IDE*     14
ID 17   PF 2     15
ID 16   PF 1     16
ID 13   PS 8     17
ID 14   PS 7     18
ID 13   PS 6     19
ID 12   PS 5     20
ID 11   PS 4     21
ID 10   PS 3     22
ID 9    PS 2     23
ID 8    PS 1     24
ID 7    SA 8     25
ID 6    SA 7     26
ID 3    SA 6     27
ID 4    SA 5     28
ID 3    SA 4     29
ID 2    SA 3     30
ID 1    SA 2     31
ID 0    SA 1     32
RTR (x) RTR*     33
r 1     r 1*     34
r 0     r 0*     35
DLC 4   DLC 4    36
DLC 3   DLC 3    37
DLC 2   DLC 2    38
DLC 1   DLC 1    39
Notes:
SOF - Start of Frame Bit P# - ISO 11783 Priority Bit #n
ID## - Identifier Bit #n R# - ISO 11783 Reserved Bit #n
SRR - Substitute Remote Request SA# - ISO 11783 Source Address Bit #n
RTR - Remote Transmission Request Bit DP - ISO 11783 Data Page
IDE - Identifier Extension Bit PF# - ISO 11783 PDU Format Bit #n
r# - CAN Reserved Bit #n PS# - ISO 11783 PDU Specific Bit #n
DLC# - Data Length Code Bit #n *CAN Defined Bit, Unchanged in ISO 11783
(d) - dominant bit 1 Required format of proprietary 11 bit identifiers
(r) - recessive bit

For NMEA2000 the R bit is always 0, but SAE J1939 it is not. J1939 calls
this the "Extended Data Page" (EDP).
*/

func getISO11783BitsFromCanID(
	id uint,
	prio *uint,
	pgn *uint,
	src *uint,
	dst *uint,
) {
	PF := id >> 16
	PS := id >> 8
	RDP := id >> 24 & 3 // Use R + DP bits

	if src != nil {
		*src = id >> 0
	}
	if prio != nil {
		*prio = (id >> 26) & 0x7
	}

	if PF < 240 {
		/* PDU1 format, the PS contains the destination address */
		if dst != nil {
			*dst = PS
		}
		if pgn != nil {
			*pgn = (RDP << 16) + (PF << 8)
		}
	} else {
		/* PDU2 format, the destination is implied global and the PGN is extended */
		if dst != nil {
			*dst = 0xff
		}
		if pgn != nil {
			*pgn = (RDP << 16) + (PF << 8) + PS
		}
	}
}

// ExitError is an error for exit codes.
type ExitError struct {
	Code  int
	Cause error
}

// Error returns the underlying error and cause.
func (e ExitError) Error() string {
	return fmt.Sprintf("exit code %d; cause=%s", e.Code, e.Cause)
}

// Unwrap returns the cause, if present.
func (e ExitError) Unwrap() error {
	return e.Cause
}
