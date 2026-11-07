PYTHON ?= python3
CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -lmspack

.PHONY: test extractor
test:
	$(PYTHON) -B -m unittest discover -s tools/service -p 'test_*.py' -v
	$(PYTHON) -B -m unittest discover -s tools/firmware -p 'test_*.py' -v

extractor: build/extract-engine

build/extract-engine: tools/firmware/extract-engine.c
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDLIBS)
