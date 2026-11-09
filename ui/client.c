#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include "process.h"
#include <stdio.h>
#include <string.h>

enum { LOG_LINES = 120, LINE_SIZE = 512 };
enum ConnectionState { DISCONNECTED, CONNECTING, CONNECTED, RECONNECTING, STOPPING, CLIENT_ERROR };
#define UI_TEXT(X) \
    X(DISCONNECTED, "未连接", "Disconnected") \
    X(CONNECTING, "正在连接…", "Connecting...") \
    X(CONNECTED, "已连接", "Connected") \
    X(RECONNECTING, "正在重连…", "Reconnecting...") \
    X(STOPPING, "正在断开…", "Disconnecting...") \
    X(CLIENT_ERROR, "客户端错误", "Client error") \
    X(SUBTITLE, "IPv4 隧道客户端", "IPv4 tunnel client") \
    X(CONNECTION, "连接配置", "Connection") \
    X(BROWSE, "浏览…", "Browse...") \
    X(CONNECT, "连接", "Connect") \
    X(DISCONNECT, "断开连接", "Disconnect") \
    X(LOG, "运行日志", "Client log") \
    X(FOLLOW, "跟随最新日志", "Follow latest") \
    X(COPY, "复制日志", "Copy log") \
    X(ADMIN, "请以管理员身份运行 XTun。", "Run XTun as administrator to connect.") \
    X(CHOOSE, "请选择客户端 CFG 配置文件。", "Choose a client CFG file to connect.") \
    X(CHECK_LOG, "请查看运行日志了解详情。", "See the client log for details.") \
    X(FILE_ERROR, "无法读取所选配置文件的路径。", "Cannot use the selected configuration path.") \
    X(START_LOG, "正在启动 XTun 客户端。", "Starting XTun client.") \
    X(EXIT_LOG, "客户端已退出，退出码：%lu。", "Client exited with code %lu.") \
    X(START_ERROR, "无法启动 XTun，Windows 错误码：%lu。", "Cannot start XTun (Windows error %lu).")
#define TEXT_ID(id, zh, en) TXT_##id,
#define TEXT_ZH(id, zh, en) zh,
#define TEXT_EN(id, zh, en) en,
#define TEXT_GLYPHS(id, zh, en) zh
enum TextId { UI_TEXT(TEXT_ID) };
static const char *const chinese_text[] = { UI_TEXT(TEXT_ZH) };
static const char *const english_text[] = { UI_TEXT(TEXT_EN) };
static const char chinese_glyphs[] = UI_TEXT(TEXT_GLYPHS);
static const char *const *text = english_text;
#undef TEXT_ID
#undef TEXT_ZH
#undef TEXT_EN
#undef TEXT_GLYPHS
#undef UI_TEXT

static Font load_ui_font(void) {
    int count = 0;
    int *glyphs = LoadCodepoints(chinese_glyphs, &count);
    int codepoints[95 + sizeof(chinese_glyphs)];
    int used = 0;
    for (int i = 32; i <= 126; ++i) codepoints[used++] = i;
    for (int i = 0; i < count; ++i) {
        int j = 0;
        while (j < used && codepoints[j] != glyphs[i]) ++j;
        if (j == used) codepoints[used++] = glyphs[i];
    }
    UnloadCodepoints(glyphs);

    char path[260];
    Font fallback = GetFontDefault();
    static const char *const candidates[] = {"Deng.ttf", "simhei.ttf"};
    for (unsigned i = 0; i < sizeof(candidates)/sizeof(*candidates); ++i) {
        if (!ui_font_path(path, sizeof(path), candidates[i]) || !FileExists(path)) continue;
        Font font = LoadFontEx(path, 36, codepoints, used);
        if (!IsFontValid(font) || !font.texture.id || font.texture.id == fallback.texture.id) continue;
        int j = 95;
        for (; j < used; ++j)
            if (font.glyphs[GetGlyphIndex(font, codepoints[j])].value != codepoints[j]) break;
        if (j == used) {
            text = chinese_text;
            return font;
        }
        UnloadFont(font);
    }
    if (ui_font_path(path, sizeof(path), "segoeui.ttf") && FileExists(path)) {
        Font font = LoadFontEx(path, 36, NULL, 0);
        if (IsFontValid(font) && font.texture.id) return font;
    }
    return fallback;
}
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

    GuiCheckBox((Rectangle){bounds.x + 98, bounds.y - 28, 16, 16}, text[TXT_FOLLOW], &follow_log);
    if (!line_count) GuiDisable();
    if (GuiButton((Rectangle){bounds.x + bounds.width - 96, bounds.y - 32, 96, 24}, text[TXT_COPY])) {
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
    Font font = load_ui_font();
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
                snprintf(output, sizeof(output), text[TXT_EXIT_LOG], exit_code);
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
        DrawTextEx(font, text[TXT_SUBTITLE], (Vector2){24, 51}, 16, 0, LIGHTGRAY);
        Color accent = state == CONNECTED ? (Color){110, 231, 164, 255} :
                       state == CLIENT_ERROR ? (Color){255, 153, 153, 255} :
                       state == DISCONNECTED ? LIGHTGRAY : (Color){253, 211, 113, 255};
        float status_x = w - 24 - MeasureTextEx(font, text[state], 18, 0).x;
        DrawCircle((int)status_x - 12, 39, 4, accent);
        DrawTextEx(font, text[state], (Vector2){status_x, 29}, 18, 0, accent);
        GuiGroupBox((Rectangle){16, 99, w - 32, 108}, text[TXT_CONNECTION]);
        if (running || closing) GuiDisable();
        if (GuiTextBox((Rectangle){28, 117, w - 162, 32}, config, sizeof(config), editing))
            editing = !editing;
        if (GuiButton((Rectangle){w - 124, 117, 96, 32}, text[TXT_BROWSE])) {
            if (ui_choose_config(config, sizeof(config), text == chinese_text) < 0)
                log_line(text[TXT_FILE_ERROR]);
            editing = 0;
        }
        GuiEnable();
        if (stopping || closing || (!running && (!admin || !config[0]))) GuiDisable();
        if (GuiButton((Rectangle){28, 160, 130, 33}, text[running ? TXT_DISCONNECT : TXT_CONNECT])) {
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
                    log_line(text[TXT_START_LOG]);
                } else {
                    snprintf(output, sizeof(output), text[TXT_START_ERROR], exit_code);
                    log_line(output);
                    state = CLIENT_ERROR;
                }
            }
        }
        GuiEnable();
        GuiLabel((Rectangle){16, 219, 88, 24}, text[TXT_LOG]);
        draw_log((Rectangle){16, 251, w - 32, h - 291});
        const char *hint = !admin ? text[TXT_ADMIN] :
                           !config[0] ? text[TXT_CHOOSE] :
                           state == CLIENT_ERROR ? text[TXT_CHECK_LOG] : text[state];
        GuiStatusBar((Rectangle){0, h - 28, w, 28}, hint);
        EndDrawing();
    }
    if (font.texture.id != GetFontDefault().texture.id) UnloadFont(font);
    CloseWindow();
    return 0;
}
