# gonmea

A partial port of https://github.com/canboat/canboat.

## Playing around

* There's `github.com/erh/gonmea/cmd/analyzer` which is the CLI for analysis of NMEA 2000 PGNs.
* There's also `github.com/erh/gonmea/cmd/parser` which is a reference if you wanted to use this as a library in another go program (e.g. `go run github.com/erh/gonmea/cmd/parser ./analyzer/tests/navlink2-test.in`)

## Note(UNTESTED)

When you see `Note(UNTESTED)` in this code, it indicates that the code has is not tested via the tests directory. The code is a best-effort port of the C code. If the relevant code is broken, get an input file and parse it with canboat (the C this codebase is ported from), then make the changes to get this library in working order.
