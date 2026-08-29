CC ?= cc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
BUILD_DIR := build
TARGET := contained
UNAME_S := $(shell uname -s)

CPPFLAGS += -Isrc $(shell $(PKG_CONFIG) --cflags libcap libseccomp 2>/dev/null)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -fstack-protector-strong
LDFLAGS ?=
LDLIBS += -lcap -lseccomp

RUNTIME_OBJECTS := $(BUILD_DIR)/contained.o $(BUILD_DIR)/config.o
UNIT_OBJECTS := $(BUILD_DIR)/test_config.o $(BUILD_DIR)/config.o
DEPS := $(RUNTIME_OBJECTS:.o=.d) $(BUILD_DIR)/test_config.d

.PHONY: all clean install test test-unit test-cli test-integration

all: $(TARGET)

$(TARGET): $(RUNTIME_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(RUNTIME_OBJECTS) $(LDLIBS)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/contained.o: src/contained.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/config.o: src/config.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/test_config.o: tests/test_config.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/test_config: $(UNIT_OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(UNIT_OBJECTS)

test-unit: $(BUILD_DIR)/test_config
	$(BUILD_DIR)/test_config

ifeq ($(UNAME_S),Linux)
test-cli: $(TARGET)
	./tests/test_cli.sh ./$(TARGET)

test-integration: $(TARGET)
	@./tests/integration.sh ./$(TARGET); status=$$?; \
	if [ $$status -eq 77 ]; then \
		echo "integration test skipped"; \
	elif [ $$status -ne 0 ]; then \
		exit $$status; \
	fi
else
test-cli:
	@echo "CLI tests skipped: Linux is required"

test-integration:
	@echo "integration test skipped: Linux is required"
endif

test: test-lines test-unit test-cli test-integration

install: $(TARGET)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

-include $(DEPS)

.PHONY: test-lines test-docker
test-lines:
	@lines=$$(awk -f tests/count_source_lines.awk src/*.c src/*.h); \
	echo "Runtime source: $$lines lines (maximum 550; comments, blank lines and formatting-only lines excluded)"; \
	test $$lines -le 550

test-docker:
	./tests/docker.sh
