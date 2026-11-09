#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include "process.h"
#include <stdio.h>
#include <string.h>

enum { LOG_LINES = 120, LINE_SIZE = 512 };
static char lines[LOG_LINES][LINE_SIZE], partial[LINE_SIZE];
static unsigned next_line, line_count, partial_len;
static const char *status = "Disconnected";

static void log_line(const char *line) {
    snprintf(lines[next_line], LINE_SIZE, "%s", line);
    next_line = (next_line + 1) % LOG_LINES;
    if (line_count < LOG_LINES) ++line_count;
}
static void consume(const char *data, int stopping) {
    for (; *data; ++data) {
        if (*data == '\r') continue;
        if (*data == '\n') {
            partial[partial_len] = 0;
            if (!stopping && !strncmp(partial, "READY ", 6)) status = "Connected";
            if (!stopping && !strncmp(partial, "session reset:", 14)) status = "Reconnecting";
            log_line(partial);
            partial_len = 0;
        } else if (partial_len < sizeof(partial) - 1) {
            partial[partial_len++] = *data;
        }
    }
}
int main(int argc, char **argv) {
    int smoke = argc == 2 && !strcmp(argv[1], "--smoke");
    char config[260] = "", output[4096];
    if (argc == 2 && !smoke) snprintf(config, sizeof(config), "%s", argv[1]);
    int admin = ui_admin(), running = 0, stopping = 0, closing = 0, editing = 0;
    unsigned long exit_code = 0;
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(780, 490, "XTun");
    if (!IsWindowReady()) return 1;
    SetWindowMinSize(550, 360);
    SetExitKey(KEY_NULL);
    SetTargetFPS(60);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, TEXT_PADDING, 8);
    for (int frames = 0; !closing || running; ++frames) {
        if (WindowShouldClose() || (smoke && frames == 3)) {
            closing = 1;
            if (running && !stopping) { ui_stop(); stopping = 1; }
            if (!running) break;
        }
        if (running) {
            running = ui_poll(output, sizeof(output), &exit_code);
            consume(output, stopping);
            if (!running) {
                if (partial_len) consume("\n", stopping);
                snprintf(output, sizeof(output), "Client exited with code %lu.", exit_code);
                log_line(output);
                status = exit_code ? "Client error" : "Disconnected";
                stopping = 0;
            }
        }
        int w = GetScreenWidth(), h = GetScreenHeight();
        BeginDrawing();
        ClearBackground((Color){239, 244, 250, 255});
        DrawRectangle(0, 0, w, 78, (Color){21, 35, 55, 255});
        DrawText("XTun", 24, 19, 34, RAYWHITE);
        DrawText("IPv4 tunnel client", 24, 56, 14, LIGHTGRAY);
        DrawText(stopping ? "Stopping..." : status, w - 174, 32, 18, RAYWHITE);
        DrawText("CLIENT CONFIGURATION", 24, 101, 15, DARKGRAY);
        if (running || closing) GuiDisable();
        if (GuiTextBox((Rectangle){24, 125, w - 154, 34}, config, sizeof(config), editing))
            editing = !editing;
        if (GuiButton((Rectangle){w - 120, 125, 96, 34}, "Browse...")) {
            ui_choose_config(config, sizeof(config));
            editing = 0;
        }
        if (!admin || !config[0]) GuiDisable();
        if (GuiButton((Rectangle){24, 174, 118, 36}, "Connect")) {
            partial_len = 0;
            editing = 0;
            if (ui_start(config, &exit_code)) {
                running = 1;
                status = "Connecting...";
                log_line("Starting XTun client.");
            } else {
                snprintf(output, sizeof(output), "Cannot start XTun (Windows error %lu).", exit_code);
                log_line(output);
                status = "Client error";
            }
        }
        GuiEnable();
        if (!running || stopping || closing) GuiDisable();
        if (GuiButton((Rectangle){152, 174, 118, 36}, "Disconnect")) {
            ui_stop();
            stopping = 1;
        }
        GuiEnable();
        if (!admin) DrawText("Run XTun as administrator to connect.", 286, 185, 14, MAROON);
        DrawText("CLIENT LOG", 24, 227, 15, DARKGRAY);
        DrawRectangle(24, 250, w - 48, h - 274, RAYWHITE);
        BeginScissorMode(32, 257, w - 64, h - 288);
        unsigned visible = (unsigned)(h - 288) / 19;
        unsigned shown = line_count < visible ? line_count : visible;
        for (unsigned i = 0; i < shown; ++i) {
            unsigned index = (next_line + LOG_LINES - shown + i) % LOG_LINES;
            DrawText(lines[index], 34, 259 + (int)i * 19, 15, DARKGRAY);
        }
        EndScissorMode();
        EndDrawing();
    }
    CloseWindow();
    return 0;
}
