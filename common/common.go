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
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"cmp"

	"go.uber.org/zap"
	"go.viam.com/rdk/logging"
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

// NewLogger returns a new logger that appends to the given writer.
func NewLogger(writer io.Writer, opts ...zap.Option) logging.Logger {
	logger := logging.NewBlankLogger("")
	logger.AddAppender(logging.ConsoleAppender{Writer: writer})
	return logger
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

// AllowPGNFastPacket returns if this PGN Fast is allowed.
func AllowPGNFastPacket(n uint32) bool {
	return (((n) >= 0x10000 && (n) < 0x1FFFF) || (n) >= CANBoatPGNStart)
}

// AllowPGNSingleFrame returns if this PGN can be in a single frame.
func AllowPGNSingleFrame(n uint32) bool {
	return ((n) < 0x10000 || (n) >= 0x1F000)
}

var (
	// UseFixedTimestamp is for testing purposes only
	UseFixedTimestamp atomic.Bool

	IsCLI atomic.Bool
)

// Now returns the current time.Time
func Now() time.Time {
	if UseFixedTimestamp.Load() {
		return time.UnixMilli(1672527600000) // 2023-01-01 00:00
	}

	return time.Now()
}

// FixedClock is used to return fixed time
type FixedClock struct{}

func (c FixedClock) Now() time.Time {
	return Now()
}

func (c FixedClock) NewTicker(t time.Duration) *time.Ticker {
	return time.NewTicker(t)
}

// Error logs a message at the ERROR level. The returned
// error may be used to propagate upwards.
func Error(logger logging.Logger, isCLI bool, format string, v ...any) error {
	logger.Errorf(format, v...)
	err := fmt.Errorf(format, v...)
	if !isCLI {
		return err
	}
	return &ExitError{Code: 2, Cause: err}
}

// Abort logs a message at the "FATAL" level. The returned
// error may be used to propagate upwards and if running
// as a CLI, it may os.Exit.
func Abort(logger logging.Logger, isCLI bool, format string, v ...any) error {
	logger.Errorf("FATAL: "+format, v...)
	err := fmt.Errorf(format, v...)
	if !isCLI {
		return err
	}
	return &ExitError{Code: 2, Cause: err}
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

// var prio, src, dst uint8
// var pgn uint32
//
//	prio, pgn, src, dst := GetISO11783BitsFromCanID(id)
//
// return prio, pgn, src, dst
func GetISO11783BitsFromCanID(id uint) (uint8, uint32, uint8, uint8) {

	PF := (id >> 16) & 0xFF
	PS := (id >> 8) & 0xFF
	RDP := id >> 24 & 3 // Use R + DP bits

	src := uint8((id >> 0) & 0xFF)
	prio := uint8((id >> 26) & 0x7)

	var pgn uint32
	var dst uint8

	if PF < 240 {
		/* PDU1 format, the PS contains the destination address */
		dst = uint8(PS)
		pgn = uint32((RDP << 16) + (PF << 8))
	} else {
		/* PDU2 format, the destination is implied global and the PGN is extended */
		dst = 0xff
		pgn = uint32((RDP << 16) + (PF << 8) + PS)
	}

	return prio, pgn, src, dst
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
