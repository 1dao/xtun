# Default to eight jobs, preserving explicit -j/--jobs and parent jobservers.
ifeq ($(MAKELEVEL),0)
ifeq ($(filter -j% --jobs% --jobserver%,$(MAKEFLAGS)),)
MAKEFLAGS += -j8
endif
endif

# One outer invocation waits for every requested goal before cleanup, so
# `make all gui test` cannot remove objects while another target uses them.
ifneq ($(XTUN_BUILD_INNER),1)
.DEFAULT_GOAL := all
.PHONY: $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all) _build
$(if $(MAKECMDGOALS),$(MAKECMDGOALS),all): _build
_build:
	+$(MAKE) XTUN_BUILD_INNER=1 $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
	+$(MAKE) XTUN_BUILD_INNER=1 clean-intermediates
else

XNET_ROOT ?= core
BIN_DIR ?= bin
CC = gcc
AR = ar
CPPFLAGS += -I$(XNET_ROOT) -I$(XNET_ROOT)/3rd/mbedtls3/include -Isrc -DXNET_WITH_UDP=1 -DXMACRO_USE_RPMALLOC=0
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -MMD -MP
ifeq ($(OS),Windows_NT)
EXT = .exe
BUILD ?= build
LDFLAGS += -static
LDLIBS += -lws2_32 -lbcrypt -ladvapi32 -liphlpapi -lwinmm
else
BUILD ?= build/linux
LDLIBS += -lpthread -lm
endif
MBED_SRCS := $(wildcard $(XNET_ROOT)/3rd/mbedtls3/library/*.c)
MBED_OBJS := $(patsubst $(XNET_ROOT)/3rd/mbedtls3/library/%.c,$(BUILD)/mbed/%.o,$(MBED_SRCS))
CORE_NAMES := xargs xudp xpoll xsock xlog xdaemon
CORE_OBJS := $(addprefix $(BUILD)/core/,$(addsuffix .o,$(CORE_NAMES)))
APP_OBJS := $(addprefix $(BUILD)/app/,$(addsuffix .o,main config tunnel platform xdtls))
TEST_APP_OBJS := $(filter-out $(BUILD)/app/main.o,$(APP_OBJS))
.PHONY: all test clean gui clean-intermediates
all: $(BIN_DIR)/xtun$(EXT)
ifeq ($(OS),Windows_NT)
PLATFORM_TEST = $(BIN_DIR)/platform_windows_test.exe
$(BIN_DIR)/platform_windows_test.exe: tests/platform_windows_test.c src/platform.c src/xtun.h $(CORE_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(CORE_OBJS) $(LDLIBS) -o $@
endif
test: $(BIN_DIR)/dtls_test$(EXT) $(BIN_DIR)/arq_test$(EXT) $(PLATFORM_TEST)
	./$(BIN_DIR)/dtls_test$(EXT)
	./$(BIN_DIR)/arq_test$(EXT)
ifeq ($(OS),Windows_NT)
	./$(BIN_DIR)/platform_windows_test.exe
endif
$(BUILD)/mbed/%.o: $(XNET_ROOT)/3rd/mbedtls3/library/%.c
	@mkdir -p $(BUILD)/mbed
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD)/core/%.o: $(XNET_ROOT)/%.c
	@mkdir -p $(BUILD)/core
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD)/app/%.o: src/%.c
	@mkdir -p $(BUILD)/app
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
$(BUILD)/mbedtls.a: $(MBED_OBJS)
	$(AR) rcs $@ $^
$(BIN_DIR)/dtls_test$(EXT): tests/dtls_test.c src/xtun.h $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
$(BIN_DIR)/arq_test$(EXT): tests/arq_test.c src/tunnel.c src/xtun.h $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(filter-out $(BUILD)/app/tunnel.o,$(TEST_APP_OBJS)) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
$(BIN_DIR)/xtun$(EXT): $(APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
-include $(wildcard $(BUILD)/core/*.d $(BUILD)/app/*.d $(BUILD)/mbed/*.d $(BUILD)/ui/*.d)
ifeq ($(OS),Windows_NT)
RAYLIB_ROOT ?= 3rd/raylib
RAYGUI_ROOT ?= 3rd/raygui
RAYLIB_STATIC ?= $(RAYLIB_ROOT)/src/libraylib.a
$(RAYLIB_STATIC):
	$(MAKE) -C "$(RAYLIB_ROOT)/src" PLATFORM=PLATFORM_DESKTOP RAYLIB_LIBTYPE=STATIC CC="$(CC)" AR="$(AR)"
# Match the compiler's resource tool, even when clang64 precedes mingw64 in PATH.
CC_TOOL_PATH := $(shell command -v $(CC))
WINDRES ?= $(dir $(CC_TOOL_PATH))windres
$(BUILD)/ui/xtun-icon.o: ui/xtun.rc ui/xtun.ico Makefile
	@mkdir -p $(BUILD)/ui
	"$(WINDRES)" -J rc -O coff -Iui -i ui/xtun.rc -o $@
$(BUILD)/ui/xtun-main.o: src/main.c src/config.h src/xtun.h
	@mkdir -p $(BUILD)/ui
	$(CC) $(CPPFLAGS) $(CFLAGS) -Dmain=xt_cli_main -c $< -o $@
gui: $(BIN_DIR)/xtun-gui.exe $(BIN_DIR)/raygui-notices.txt
$(BIN_DIR)/xtun-gui.exe: ui/client.c ui/process.c ui/process.h ui/tray.c ui/tray.h ui/client_config.c ui/client_config.h src/config.h $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(BUILD)/ui/xtun-main.o $(BUILD)/ui/xtun-icon.o $(RAYLIB_STATIC) $(RAYGUI_ROOT)/src/raygui.h Makefile
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD -MP,$(CFLAGS)) $(LDFLAGS) -isystem "$(RAYLIB_ROOT)/src" -isystem "$(RAYGUI_ROOT)/src" -mwindows ui/client.c ui/process.c ui/tray.c ui/client_config.c $(BUILD)/ui/xtun-main.o $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(BUILD)/ui/xtun-icon.o "$(RAYLIB_STATIC)" -lopengl32 -lgdi32 -lshell32 $(LDLIBS) -o $@
$(BIN_DIR)/raygui-notices.txt: $(wildcard ui/vendor/*LICENSE.txt)
	@mkdir -p $(BIN_DIR)
	cat $^ > $@
else
gui:
	@echo "The XTun GUI is available on Windows." && exit 1
endif
clean:
	$(RM) $(BUILD)/core/*.o $(BUILD)/core/*.d $(BUILD)/app/*.o $(BUILD)/app/*.d $(BUILD)/mbed/*.o $(BUILD)/mbed/*.d $(BUILD)/mbedtls.a $(BIN_DIR)/xtun$(EXT) $(BIN_DIR)/dtls_test$(EXT) $(BIN_DIR)/arq_test$(EXT)
ifeq ($(OS),Windows_NT)
	$(RM) $(BIN_DIR)/xtun-gui.exe $(BIN_DIR)/raygui-notices.txt $(BIN_DIR)/platform_windows_test.exe
	$(RM) $(BUILD)/ui/xtun-icon.o $(BUILD)/ui/xtun-main.o $(BUILD)/ui/xtun-main.d
endif
clean-intermediates:
	$(RM) $(BIN_DIR)/xtun.d $(BIN_DIR)/dtls_test.d $(BIN_DIR)/arq_test.d $(BIN_DIR)/platform_windows_test.d
ifeq ($(OS),Windows_NT)
	$(RM) $(BIN_DIR)/xtun.exp $(BIN_DIR)/xtun.lib $(BIN_DIR)/xtun.ilk $(BIN_DIR)/xtun-gui.exp $(BIN_DIR)/xtun-gui.lib $(BIN_DIR)/xtun-gui.ilk
ifeq ($(abspath $(RAYLIB_ROOT)),$(abspath 3rd/raylib))
	$(RM) $(addprefix $(RAYLIB_ROOT)/src/,rcore.o rshapes.o rtextures.o rtext.o rglfw.o rmodels.o raudio.o libraylib.a)
endif
	powershell -NoProfile -Command "Get-ChildItem -LiteralPath '$(BUILD)' -Force | Remove-Item -Recurse -Force -ErrorAction Stop"
else
	$(RM) -r $(BUILD)/* $(BUILD)/.[!.]* $(BUILD)/..?*
endif
endif # XTUN_BUILD_INNER
