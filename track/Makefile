.DEFAULT_GOAL := all
PIN_ROOT ?= $(CURDIR)/.deps/pin
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(PIN_ROOT)/source/tools/Config/makefile.config
TOOL_ROOTS := pretrace
TOOL_CXXFLAGS += -std=c++17 -O3 -g -Isrc -Wno-error=maybe-uninitialized
VPATH := src
include $(TOOLS_ROOT)/Config/makefile.default.rules
.PHONY: all unit integration mcp-test test
all: obj-intel64/pretrace.so
obj-intel64/pretrace.o: src/taint_core.hpp src/comparison_model.hpp
unit:
	mkdir -p build
	g++ -std=c++17 -O2 -g -Wall -Wextra -Werror -Isrc tests/core_test.cpp -o build/core_test
	./build/core_test
integration: all
	python3 tests/integration.py
mcp-test:
	python3 tests/mcp_test.py
test: unit integration mcp-test
.PHONY: sanitize benchmark
sanitize:
	mkdir -p build
	g++ -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Isrc tests/core_test.cpp -o build/core_sanitize
	ASAN_OPTIONS=detect_leaks=1 ./build/core_sanitize
benchmark:
	mkdir -p build
	g++ -std=c++17 -O3 -Isrc tests/benchmark.cpp -o build/benchmark
	./build/benchmark
# GCC 15 diagnoses Pin's bundled libc++ __hash_table as maybe-uninitialized at -O3.
# Keep the warning visible without disabling -Werror for other diagnostic classes.
