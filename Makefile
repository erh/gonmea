# Originally from https://github.com/canboat/canboat (Apache License, Version 2.0)
# (C) 2009-2023, Kees Verruijt, Harlingen, The Netherlands.
#  
# This file is part of CANboat.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

TOOL_BIN = bin/gotools/$(shell uname -s)-$(shell uname -m)
PATH_WITH_TOOLS="`pwd`/$(TOOL_BIN):${PATH}"
PLATFORM=$(shell uname | tr '[A-Z]' '[a-z]')-$(shell uname -m)
BUILDDIR?=rel/$(PLATFORM)
TARGETDIR=$(BUILDDIR)
ANALYZER=$(TARGETDIR)/analyzer_cli
ANALYZER_LIB=$(TARGETDIR)/analyzer_lib
TARGETS=$(ANALYZER) $(ANALYZER_LIB)

all: $(TARGETS)

analyzer: $(ANALYZER)

analyzer_lib: $(ANALYZER)

$(ANALYZER):
	@mkdir -p $(TARGETDIR)
	go build -o $(ANALYZER) cmd/analyzer_cli/main.go
	go build -o $(ANALYZER_LIB) cmd/analyzer_lib/main.go

tests:	$(ANALYZER)
	go test -v -race ./...
	(cd analyzer/tests; make tests)

tool-install:
	GOBIN=`pwd`/$(TOOL_BIN) go install github.com/edaniels/golinters/cmd/combined \
		github.com/golangci/golangci-lint/cmd/golangci-lint

lint: tool-install
	go vet -vettool=$(TOOL_BIN)/combined ./...
	GOGC=50 $(TOOL_BIN)/golangci-lint run -v --fix --config=./etc/.golangci.yaml

.PHONY:	$(ANALYZER) tests
