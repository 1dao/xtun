#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include "process.h"
#include <stdio.h>
#include <string.h>

enum { LOG_LINES = 120, LINE_SIZE = 512 };
enum ConnectionState { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, STOPPING, CLIENT_ERROR };
static const char *const state_text[] = {
    "Disconnected", "Connecting...", "Connected", "Reconnecting...", "Disconnecting...", "Client error"
};
static char lines[LOG_LINES][LINE_SIZE], partial[LINE_SIZE];
static unsigned next_line, partial_len;
static int line_count, log_scroll;
static bool follow_log = true;
static enum ConnectionState state = DISCONNECTED;

static void log_line(const char *line) {
    snprintf(lines[next_line], LINE_SIZE, "%s", line);
    next_line = (next_line + 1) % LOG_LINES;
    if (line_count < LOG_LINES) ++line_count;
    else if (!follow_log && log_scroll > 0) --log_scroll;
}
static void consume(const char *data, int stopping) {
    for (; *data; ++data) {
        if (*data == '\r') continue;
        if (*data == '\n') {
            partial[partial_len] = 0;
            if (!stopping && !strncmp(partial, "READY ", 6)) state = CONNECTED;
            if (!stopping && !strncmp(partial, "session reset:", 14)) state = RECONNECTING;
            log_line(partial);
            partial_len = 0;
        } else if (partial_len < sizeof(partial) - 1) {
            partial[partial_len++] = *data;
        }
    }
}
static void draw_log(Rectangle bounds) {
    char *items[LOG_LINES];
    for (int i = 0; i < line_count; ++i)
        items[i] = lines[(next_line + LOG_LINES - line_count + i) % LOG_LINES];
    int row = GuiGetStyle(LISTVIEW, LIST_ITEMS_HEIGHT) + GuiGetStyle(LISTVIEW, LIST_ITEMS_SPACING);
    int last = line_count - (int)bounds.height / row;
    if (last < 0) last = 0;
    if (follow_log || log_scroll > last) log_scroll = last;
    BeginScissorMode((int)bounds.x, (int)bounds.y, (int)bounds.width, (int)bounds.height);
    GuiListViewEx(bounds, items, line_count, &log_scroll, NULL, NULL);
    EndScissorMode();
    if (log_scroll < last) follow_log = false;

    GuiCheckBox((Rectangle){bounds.x + 98, bounds.y - 28, 16, 16}, "Follow latest", &follow_log);
    if (!line_count) GuiDisable();
    if (GuiButton((Rectangle){bounds.x + bounds.width - 96, bounds.y - 32, 96, 24}, "Copy log")) {
        char clipboard[LOG_LINES * (LINE_SIZE + 1) + 1];
        size_t used = 0;
        for (int i = 0; i < line_count; ++i) {
            size_t len = strlen(items[i]);
            memcpy(clipboard + used, items[i], len);
            used += len;
            clipboard[used++] = '\n';
        }
        clipboard[used] = 0;
        SetClipboardText(clipboard);
    }
    GuiEnable();
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
    char font_path[260];
    Font font = GetFontDefault();
    if (ui_font_path(font_path, sizeof(font_path))) {
        Font system_font = LoadFontEx(font_path, 36, NULL, 0);
        if (IsFontValid(system_font) && system_font.texture.id) font = system_font;
    }
    if (font.texture.id != GetFontDefault().texture.id)
        SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(font);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, TEXT_PADDING, 8);
    GuiSetStyle(LISTVIEW, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
    GuiSetStyle(LISTVIEW, LIST_ITEMS_HEIGHT, 24);
    GuiSetStyle(LISTVIEW, LIST_ITEMS_SPACING, 2);
    for (int frames = 0; !closing || running; ++frames) {
        if (WindowShouldClose() || (smoke && frames == 3)) {
            closing = 1;
            if (running && !stopping) { ui_stop(); stopping = 1; state = STOPPING; }
            if (!running) break;
        }
        if (running) {
            running = ui_poll(output, sizeof(output), &exit_code);
            consume(output, stopping);
            if (!running) {
                if (partial_len) consume("\n", stopping);
                snprintf(output, sizeof(output), "Client exited with code %lu.", exit_code);
                log_line(output);
                state = exit_code ? CLIENT_ERROR : DISCONNECTED;
                stopping = 0;
            }
        }
        int w = GetScreenWidth(), h = GetScreenHeight();
        BeginDrawing();
        ClearBackground((Color){239, 244, 250, 255});
        DrawRectangle(0, 0, w, 78, (Color){21, 35, 55, 255});
        DrawTextEx(font, "XTun", (Vector2){24, 12}, 34, 1, RAYWHITE);
        DrawTextEx(font, "IPv4 tunnel client", (Vector2){24, 51}, 16, 0, LIGHTGRAY);
        Color accent = state == CONNECTED ? (Color){110, 231, 164, 255} :
                       state == CLIENT_ERROR ? (Color){255, 153, 153, 255} :
                       state == DISCONNECTED ? LIGHTGRAY : (Color){253, 211, 113, 255};
        float status_x = w - 24 - MeasureTextEx(font, state_text[state], 18, 0).x;
        DrawCircle((int)status_x - 12, 39, 4, accent);
        DrawTextEx(font, state_text[state], (Vector2){status_x, 29}, 18, 0, accent);
        GuiGroupBox((Rectangle){16, 99, w - 32, 108}, "Connection");
        if (running || closing) GuiDisable();
        if (GuiTextBox((Rectangle){28, 117, w - 162, 32}, config, sizeof(config), editing))
            editing = !editing;
        if (GuiButton((Rectangle){w - 124, 117, 96, 32}, "Browse...")) {
            ui_choose_config(config, sizeof(config));
            editing = 0;
        }
        GuiEnable();
        if (stopping || closing || (!running && (!admin || !config[0]))) GuiDisable();
        if (GuiButton((Rectangle){28, 160, 130, 33}, running ? "Disconnect" : "Connect")) {
            if (running) {
                ui_stop();
                stopping = 1;
                state = STOPPING;
            } else {
                partial_len = 0;
                editing = 0;
                if (ui_start(config, &exit_code)) {
                    running = 1;
                    state = CONNECTING;
                    log_line("Starting XTun client.");
                } else {
                    snprintf(output, sizeof(output), "Cannot start XTun (Windows error %lu).", exit_code);
                    log_line(output);
                    state = CLIENT_ERROR;
                }
            }
        }
        GuiEnable();
        GuiLabel((Rectangle){16, 219, 88, 24}, "Client log");
        draw_log((Rectangle){16, 251, w - 32, h - 291});
        const char *hint = !admin ? "Run XTun as administrator to connect." :
                           !config[0] ? "Choose a client CFG file to connect." :
                           state == CLIENT_ERROR ? "See the client log for details." : state_text[state];
        GuiStatusBar((Rectangle){0, h - 28, w, 28}, hint);
        EndDrawing();
    }
    if (font.texture.id != GetFontDefault().texture.id) UnloadFont(font);
    CloseWindow();
    return 0;
}
