package analyzer

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

// A Printer can print various types of PGN fields/info.
type Printer interface {
	PrintFieldNumber(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldFloat(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldDecimal(
		_ *PGNField,
		_ string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldLookup(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldBitLookup(
		field *PGNField,
		_ string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldBinary(
		field *PGNField,
		_ string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldReserved(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldSpare(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldMMSI(
		field *PGNField,
		_ string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldKeyValue(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldLatLon(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldDate(
		_ *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldStringFix(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldStringLZ(
		_ *PGNField,
		_ string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldStringLAU(
		_ *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldTime(
		field *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
	PrintFieldVariable(
		_ *PGNField,
		fieldName string,
		data []byte,
		startBit int,
		bits *int,
	) (bool, error)
}
