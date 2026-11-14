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
.PHONY: all test clean gui
all: $(BIN_DIR)/xtun$(EXT)
ifeq ($(OS),Windows_NT)
PLATFORM_TEST = $(BIN_DIR)/platform_windows_test.exe
$(BIN_DIR)/platform_windows_test.exe: tests/platform_windows_test.c src/platform.c src/xtun.h $(CORE_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(CORE_OBJS) $(LDLIBS) -o $@
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
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
$(BIN_DIR)/arq_test$(EXT): tests/arq_test.c src/tunnel.c src/xtun.h $(TEST_APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(filter-out $(BUILD)/app/tunnel.o,$(TEST_APP_OBJS)) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
$(BIN_DIR)/xtun$(EXT): $(APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(APP_OBJS) $(CORE_OBJS) $(BUILD)/mbedtls.a $(LDLIBS) -o $@
-include $(wildcard $(BUILD)/core/*.d $(BUILD)/app/*.d $(BUILD)/mbed/*.d)
ifeq ($(OS),Windows_NT)
RAYLIB_ROOT ?= ../../ops/raylib
RAYGUI_ROOT ?= ../../ops/raygui
RAYLIB_STATIC ?= $(RAYLIB_ROOT)/src/libraylib.a
WINDRES ?= windres
$(BUILD)/ui/xtun-icon.o: ui/xtun.rc ui/xtun.ico
	@mkdir -p $(BUILD)/ui
	$(WINDRES) -Iui -i ui/xtun.rc -o $@
gui: $(BIN_DIR)/xtun.exe $(BIN_DIR)/xtun-gui.exe $(BIN_DIR)/raygui-notices.txt
$(BIN_DIR)/xtun-gui.exe: ui/client.c ui/process.c ui/process.h ui/tray.c ui/tray.h ui/client_config.c ui/client_config.h src/config.h $(BUILD)/app/config.o $(BUILD)/core/xargs.o $(BUILD)/ui/xtun-icon.o $(RAYLIB_STATIC) $(RAYGUI_ROOT)/src/raygui.h
	@mkdir -p $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(filter-out -MMD -MP,$(CFLAGS)) -isystem "$(RAYLIB_ROOT)/src" -isystem "$(RAYGUI_ROOT)/src" -mwindows ui/client.c ui/process.c ui/tray.c ui/client_config.c $(BUILD)/app/config.o $(BUILD)/core/xargs.o $(BUILD)/ui/xtun-icon.o "$(RAYLIB_STATIC)" -lopengl32 -lgdi32 -lwinmm -lshell32 -ladvapi32 -lws2_32 -o $@
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
	$(RM) $(BUILD)/ui/xtun-icon.o
endif
