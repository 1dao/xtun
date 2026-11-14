#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"
#include "process.h"
#include "client_config.h"
#include <stdio.h>
#include <string.h>

enum { LOG_LINES = 120, LINE_SIZE = 1024 };
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
    X(EDIT, "编辑", "Edit") \
    X(REMOVE, "移除", "Remove") \
    X(REMOVE_HINT, "从 client.cfg 移除此配置？", "Remove this profile from client.cfg?") \
    X(REMOVE_OPTIONS, "移除;取消", "Remove;Cancel") \
    X(SWITCH, "切换连接", "Switch connection") \
    X(DETAILS, "隧道信息", "Tunnel details") \
    X(SERVER, "服务器地址", "Server endpoint") \
    X(ADDRESS, "本地隧道地址", "Local tunnel address") \
    X(PEER, "对端隧道地址", "Peer tunnel address") \
    X(MODE, "路由模式", "Routing mode") \
    X(SPLIT, "IPv4 分流", "IPv4 split tunnel") \
    X(FULL, "IPv4 全局", "IPv4 full tunnel") \
    X(ONE, "一次连接一个配置", "One active connection") \
    X(AUTORUN, "开机启动", "Start at sign-in") \
    X(AUTORUN_ERROR, "无法保存开机启动设置。", "Could not save the startup setting.") \
    X(AUTORUN_DIR_ERROR, "启动目录不可用，请手动重新打开 XTun。", "Startup directory unavailable. Open XTun manually.") \
    X(EMPTY, "还没有连接配置", "No connection profiles") \
    X(EMPTY_HINT, "点击左侧的 +，新建客户端配置。", "Use + on the left to create a profile.") \
    X(UNAVAILABLE, "配置文件不可用", "Configuration file unavailable") \
    X(INVALID_CFG, "配置校验失败，请检查 CFG 和密钥。", "Configuration check failed. Verify the CFG and PSK.") \
    X(STORE_ERROR, "无法读取或保存 client.cfg。", "Could not read or save client.cfg.") \
    X(LIMIT, "配置列表已满。", "The profile list is full.") \
    X(EDIT_WHILE_ACTIVE, "请先断开当前隧道，再管理配置。", "Disconnect the current tunnel before managing profiles.") \
    X(ERROR_TITLE, "操作失败", "Operation failed") \
    X(OK, "确定", "OK") \
    X(CONNECT, "连接", "Connect") \
    X(DISCONNECT, "断开连接", "Disconnect") \
    X(LOG, "运行日志", "Client log") \
    X(FOLLOW, "跟随最新日志", "Follow latest") \
    X(COPY, "复制日志", "Copy log") \
    X(ADMIN, "请以管理员身份运行 XTun。", "Run XTun as administrator to connect.") \
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

static Profile profiles[PROFILE_LIMIT];
static ProfileInfo details[PROFILE_LIMIT];
static int profile_count, selected = -1, active = -1, pending = -1, failed = -1, profile_scroll;

static Font load_ui_font(void) {
    int count = 0;
    int *glyphs = LoadCodepoints(chinese_glyphs, &count);
    int codepoints[95 + sizeof(chinese_glyphs) + PROFILE_LIMIT * 40];
    int used = 0;
    for (int i = 32; i <= 126; ++i) codepoints[used++] = i;
    for (int i = 0; i < count; ++i) {
        int j = 0;
        while (j < used && codepoints[j] != glyphs[i]) ++j;
        if (j == used) codepoints[used++] = glyphs[i];
    }
    UnloadCodepoints(glyphs);
    int required = used;
    for (int i = 0; i < profile_count; ++i) {
        glyphs = LoadCodepoints(profiles[i].name, &count);
        for (int n = 0; n < count && used < (int)(sizeof(codepoints)/sizeof(*codepoints)); ++n) {
            int j = 0;
            while (j < used && codepoints[j] != glyphs[n]) ++j;
            if (j == used) codepoints[used++] = glyphs[n];
        }
        UnloadCodepoints(glyphs);
    }

    char path[260];
    Font fallback = GetFontDefault();
    static const char *const candidates[] = {"Deng.ttf", "simhei.ttf"};
    for (unsigned i = 0; i < sizeof(candidates)/sizeof(*candidates); ++i) {
        if (!ui_font_path(path, sizeof(path), candidates[i]) || !FileExists(path)) continue;
        Font font = LoadFontEx(path, 36, codepoints, used);
        if (!IsFontValid(font) || !font.texture.id || font.texture.id == fallback.texture.id) continue;
        int j = 95;
        for (; j < required; ++j)
            if (font.glyphs[GetGlyphIndex(font, codepoints[j])].value != codepoints[j]) break;
        if (j == required) {
            text = chinese_text;
            return font;
        }
        UnloadFont(font);
    }
    text = english_text;
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
static bool cleanup_failed;
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
            if (!strncmp(partial, "route cleanup failed:", 21)) cleanup_failed = true;
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
static void set_font(Font font) {
    if (font.texture.id != GetFontDefault().texture.id)
        SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(font);
}
static void release_font(Font font) {
    if (font.texture.id != GetFontDefault().texture.id) UnloadFont(font);
}
static const Color ink = {24, 35, 39, 255}, muted = {81, 97, 103, 255};
static const Color teal = {12, 105, 97, 255}, active_color = {26, 129, 82, 255};
static const Color rule = {220, 228, 229, 255};

static void caption(const char *value, int x, int y, int size, Color color) {
    DrawTextEx(GuiGetFont(), value, (Vector2){x, y}, (float)size, 0, color);
}
static void clipped_caption(const char *value, int x, int y, int width, int size, Color color) {
    BeginScissorMode(x, y, width, size + 5);
    caption(value, x, y, size, color);
    EndScissorMode();
}
static void round_box(Rectangle bounds, float radius, Color color) {
    DrawRectangleRounded(bounds, radius, 8, color);
}
static int primary_button(Rectangle bounds, const char *label) {
    static const int props[] = {BORDER_COLOR_NORMAL, BASE_COLOR_NORMAL, TEXT_COLOR_NORMAL,
                               BORDER_COLOR_FOCUSED, BASE_COLOR_FOCUSED, TEXT_COLOR_FOCUSED};
    const int colors[] = {0x0C6961FF, 0x0C6961FF, (int)0xFFFFFFFF,
                          0x07554EFF, 0x07554EFF, (int)0xFFFFFFFF};
    int saved[6];
    for (int i = 0; i < 6; ++i) {
        saved[i] = GuiGetStyle(BUTTON, props[i]);
        GuiSetStyle(BUTTON, props[i], colors[i]);
    }
    int pressed = GuiButton(bounds, label);
    for (int i = 0; i < 6; ++i) GuiSetStyle(BUTTON, props[i], saved[i]);
    return pressed;
}
static const char *mode(const ProfileInfo *info) {
    return !info->available ? text[TXT_UNAVAILABLE] : text[info->full ? TXT_FULL : TXT_SPLIT];
}

enum Action { NONE, EDIT, REMOVE, NEW_PROFILE, CONFIRM_REMOVE, CONNECT_PROFILE };
enum Dialog { NO_DIALOG, REMOVE_DIALOG, ERROR_DIALOG };
static int menu_profile = -1;
static bool autorun, autorun_error;

static enum Action sidebar(int width, int height, int modal) {
    DrawRectangle(0, 0, width, height, (Color){244, 247, 248, 255});
    DrawLine(width - 1, 0, width - 1, height, rule);
    caption(text[TXT_CONNECTION], 20, 29, 22, ink);
    int badge_x = 28 + (int)MeasureTextEx(GuiGetFont(), text[TXT_CONNECTION], 22, 0).x;
    char count[8];
    snprintf(count, sizeof(count), "%d", profile_count);
    round_box((Rectangle){badge_x, 29, 27, 23}, 0.38f, (Color){229, 236, 236, 255});
    caption(count, badge_x + (profile_count < 10 ? 10 : 6), 32, 15, muted);
    int plus_x = badge_x + 35;
    if (plus_x > width - 42) plus_x = width - 42;
    Rectangle plus = {plus_x, 24, 30, 30};
    int border = GuiGetStyle(BUTTON, BORDER_COLOR_NORMAL);
    int base = GuiGetStyle(BUTTON, BASE_COLOR_NORMAL);
    GuiSetStyle(BUTTON, BORDER_COLOR_NORMAL, 0);
    GuiSetStyle(BUTTON, BASE_COLOR_NORMAL, 0);
    if (menu_profile >= 0) GuiDisable();
    int add = GuiButton(plus, "");
    if (menu_profile >= 0) GuiEnable();
    GuiSetStyle(BUTTON, BORDER_COLOR_NORMAL, border);
    GuiSetStyle(BUTTON, BASE_COLOR_NORMAL, base);
    DrawLineEx((Vector2){plus.x + 8, plus.y + 15}, (Vector2){plus.x + 22, plus.y + 15}, 2, teal);
    DrawLineEx((Vector2){plus.x + 15, plus.y + 8}, (Vector2){plus.x + 15, plus.y + 22}, 2, teal);

    int visible = (height - 154) / 63;
    int last = profile_count > visible ? profile_count - visible : 0;
    Rectangle region = {12, 75, width - 24, visible * 63};
    Vector2 mouse = GetMousePosition();
    if (!modal && menu_profile < 0 && CheckCollisionPointRec(mouse, region)) profile_scroll -= (int)GetMouseWheelMove();
    if (profile_scroll > last) profile_scroll = last;
    if (profile_scroll < 0) profile_scroll = 0;
    int end = profile_scroll + visible;
    if (end > profile_count) end = profile_count;
    int open = menu_profile;
    if (modal || open < profile_scroll || open >= end) open = menu_profile = -1;
    for (int i = profile_scroll; i < end; ++i) {
        int y = 75 + (i - profile_scroll) * 63;
        Rectangle row = {12, y, width - 26, 55};
        int hover = !modal && CheckCollisionPointRec(mouse, row);
        Rectangle dots = {width - 48, y + 12, 28, 30};
        int dot_hover = CheckCollisionPointRec(mouse, dots);
        if (hover && open < 0 && IsMouseButtonReleased(MOUSE_BUTTON_LEFT)) {
            if (dot_hover) menu_profile = i;
            else selected = i;
        }
        if (selected == i) {
            round_box(row, 0.18f, (Color){220, 239, 235, 255});
            DrawRectangle(12, y + 8, 3, 39, teal);
        } else if (hover) round_box(row, 0.18f, (Color){232, 239, 240, 255});
        if (i == active) DrawCircle(width - 57, y + 19, 4, state == CONNECTED ? active_color : teal);
        clipped_caption(profiles[i].name, 24, y + 8, width - 89, 19, ink);
        clipped_caption(i == active ? text[state] : mode(&details[i]), 24, y + 32, width - 75, 15, muted);
        if ((hover && dot_hover) || menu_profile == i)
            round_box(dots, 0.24f, (Color){203, 226, 221, 255});
        for (int dot = 0; dot < 3; ++dot)
            DrawCircle(width - 34, y + 21 + 6 * dot, 1.6f, muted);
    }
    if (last > 0) {
        int track = visible * 63 - 8;
        int thumb = track * visible / profile_count;
        if (thumb < 16) thumb = 16;
        DrawRectangle(width - 8, 75 + (track - thumb) * profile_scroll / last, 3, thumb, rule);
    }
    if (menu_profile >= 0) GuiDisable();
    bool requested = autorun;
    GuiCheckBox((Rectangle){20, height - 60, 16, 16}, text[TXT_AUTORUN], &requested);
    if (requested != autorun) {
        if (ui_set_autorun(requested)) autorun = requested;
        else autorun_error = true;
    }
    if (menu_profile >= 0) GuiEnable();
    caption(text[TXT_ONE], 20, height - 27, 15, muted);
    if (open >= 0) {
        int y = 75 + (open - profile_scroll) * 63 + 44;
        if (y + 70 > height) y -= 102;
        Rectangle popup = {width - 132, y, 112, 70};
        DrawRectangleRec(popup, WHITE);
        DrawRectangleLinesEx(popup, 1, rule);
        if (active >= 0) GuiDisable();
        int edit = GuiButton((Rectangle){popup.x + 4, popup.y + 4, 104, 29}, text[TXT_EDIT]);
        int remove = GuiButton((Rectangle){popup.x + 4, popup.y + 37, 104, 29}, text[TXT_REMOVE]);
        GuiEnable();
        if (edit || remove) {
            selected = open;
            menu_profile = -1;
            return edit ? EDIT : REMOVE;
        }
        if (IsKeyPressed(KEY_ESCAPE) ||
            (IsMouseButtonReleased(MOUSE_BUTTON_LEFT) && !CheckCollisionPointRec(mouse, popup)))
            menu_profile = -1;
    }
    return add ? NEW_PROFILE : NONE;
}

static enum Action workspace(int left, int width, int height, int admin, int locked, bool *log_open) {
    int x = left + 24, w = width - x - 24;
    int footer = height - 33;
    if (selected < 0) {
        caption(text[TXT_EMPTY], x, 36, 28, ink);
        caption(text[TXT_EMPTY_HINT], x, 83, 17, muted);
        return NONE;
    }
    const ProfileInfo *info = &details[selected];
    clipped_caption(profiles[selected].name, x, 22, w, 31, ink);
    caption(text[TXT_SUBTITLE], x, 60, 16, muted);
    enum Action action = NONE;

    enum ConnectionState visible_state = active == selected ? state :
        (active < 0 && selected == failed ? CLIENT_ERROR : DISCONNECTED);
    Color dot = visible_state == CONNECTED ? active_color :
                visible_state == CLIENT_ERROR ? (Color){180, 56, 56, 255} :
                visible_state == DISCONNECTED ? muted : (Color){173, 113, 24, 255};
    Color banner = visible_state == CONNECTED ? (Color){226, 242, 237, 255} :
                                                (Color){241, 246, 247, 255};
    round_box((Rectangle){x, 93, w, 66}, 0.20f, banner);
    DrawCircle(x + 17, 115, 5, dot);
    caption(text[visible_state], x + 29, 103, 21, ink);
    clipped_caption(mode(info), x + 29, 131, w - 187, 15, muted);
    if (locked || pending >= 0 || state == STOPPING ||
        (active != selected && (!admin || !info->available))) GuiDisable();
    const char *operation = text[active == selected ? TXT_DISCONNECT : active >= 0 ? TXT_SWITCH : TXT_CONNECT];
    if (primary_button((Rectangle){x + w - 135, 109, 120, 34}, operation)) action = CONNECT_PROFILE;
    GuiEnable();

    caption(text[TXT_DETAILS], x, 176, 21, ink);
    static const int keys[] = {TXT_SERVER, TXT_ADDRESS, TXT_PEER, TXT_MODE};
    const char *values[] = {info->endpoint, info->address, info->peer, mode(info)};
    for (int i = 0; i < 4; ++i) {
        int y = 204 + 30*i;
        DrawLine(x, y, x + w, y, rule);
        caption(text[keys[i]], x, y + 6, 16, muted);
        clipped_caption(*values[i] ? values[i] : "-", x + 155, y + 6, w - 155, 16, ink);
    }
    DrawLine(x, 324, x + w, 324, rule);

    if (GuiButton((Rectangle){x, 342, w, 29}, "")) *log_open = !*log_open;
    caption(*log_open ? "v" : ">", x + 12, 348, 16, teal);
    caption(text[TXT_LOG], x + 31, 348, 16, ink);
    if (*log_open) draw_log((Rectangle){x, 408, w, footer - 416});
    return action;
}

static void start_profile(int index) {
    char output[256];
    unsigned long error = 0;
    partial_len = 0;
    if (ui_start(profiles[index].tag, &error)) {
        active = index;
        failed = -1;
        state = CONNECTING;
        log_line(text[TXT_START_LOG]);
    } else {
        snprintf(output, sizeof(output), text[TXT_START_ERROR], error);
        log_line(output);
        state = CLIENT_ERROR;
        failed = index;
    }
}
int main(int argc, char **argv) {
    int smoke = argc == 2 && !strcmp(argv[1], "--smoke");
    int boot = argc > 1 && !strcmp(argv[1], "--autostart");
    int directory_ok = !boot || ui_autorun_workdir();
    autorun = smoke ? false : ui_get_autorun();
    int admin = ui_admin(), closing = 0;
    bool log_open = false;
    enum Dialog dialog = NO_DIALOG;
    int error_text = TXT_STORE_ERROR;
    int loaded = smoke || !directory_ok ? 0 : client_configs_load(profiles, details);
    if (!directory_ok) { dialog = ERROR_DIALOG; error_text = TXT_AUTORUN_DIR_ERROR; }
    if (loaded < 0) dialog = ERROR_DIALOG;
    else {
        profile_count = loaded;
        if (profile_count) selected = 0;
    }
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(920, 580, "XTun");
    if (!IsWindowReady()) return 1;
    SetWindowMinSize(730, 510);
    SetExitKey(KEY_NULL);
    SetTargetFPS(60);
    Font font = load_ui_font();
    set_font(font);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 16);
    GuiSetStyle(DEFAULT, TEXT_SPACING, 0);
    GuiSetStyle(DEFAULT, TEXT_PADDING, 8);
    GuiSetStyle(DEFAULT, BORDER_COLOR_NORMAL, 0xC2D0D1FF);
    GuiSetStyle(DEFAULT, BASE_COLOR_NORMAL, 0xF8FAFAFF);
    GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL, 0x182327FF);
    GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED, 0x6D9C96FF);
    GuiSetStyle(DEFAULT, BASE_COLOR_FOCUSED, 0xE2F0EDFF);
    GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED, 0x0C6961FF);
    GuiSetStyle(DEFAULT, BACKGROUND_COLOR, 0xFFFFFFFF);
    GuiSetStyle(LISTVIEW, TEXT_ALIGNMENT, TEXT_ALIGN_LEFT);
    GuiSetStyle(LISTVIEW, LIST_ITEMS_HEIGHT, 24);
    GuiSetStyle(LISTVIEW, LIST_ITEMS_SPACING, 2);
    for (int frames = 0; !closing || active >= 0; ++frames) {
        if (WindowShouldClose() || (smoke && frames == 3)) {
            closing = 1;
            pending = -1;
            if (active >= 0 && state != STOPPING) { ui_stop(); state = STOPPING; }
            if (active < 0) break;
        }
        if (active >= 0) {
            char output[4096];
            unsigned long exit_code = 0;
            int running = ui_poll(output, sizeof(output), &exit_code);
            consume(output, state == STOPPING);
            if (!running) {
                if (partial_len) consume("\n", state == STOPPING);
                snprintf(output, sizeof(output), text[TXT_EXIT_LOG], exit_code);
                log_line(output);
                state = exit_code || cleanup_failed ? CLIENT_ERROR : DISCONNECTED;
                failed = state == CLIENT_ERROR ? active : -1;
                active = -1;
                if (state == CLIENT_ERROR) log_open = true;
                int next = pending;
                pending = -1;
                if (!closing && next >= 0 && state == DISCONNECTED) start_profile(next);
                cleanup_failed = false;
            }
        }
        int w = GetScreenWidth(), h = GetScreenHeight(), split = w < 820 ? 224 : 258;
        BeginDrawing();
        ClearBackground(RAYWHITE);
        int modal = dialog != NO_DIALOG || closing;
        if (modal) GuiLock();
        int menu_open = menu_profile >= 0;
        enum Action action = sidebar(split, h - 33, modal);
        if (menu_open || menu_profile >= 0) GuiLock();
        enum Action main_action = workspace(split, w, h, admin, modal || menu_open, &log_open);
        if (main_action != NONE) action = main_action;
        DrawRectangle(0, h - 33, w, 33, (Color){242, 246, 247, 255});
        DrawLine(0, h - 33, w, h - 33, rule);
        const char *hint = !admin ? text[TXT_ADMIN] : state == CLIENT_ERROR ? text[TXT_CHECK_LOG] : text[state];
        if (active >= 0) {
            DrawCircle(19, h - 16, 4, state == CONNECTED ? active_color : teal);
            caption(text[state], 31, h - 25, 16, ink);
            int offset = 47 + (int)MeasureTextEx(font, text[state], 16, 0).x;
            clipped_caption(profiles[active].name, offset, h - 25, w - offset - 15, 16, muted);
        } else caption(hint, 18, h - 25, 16, muted);
        GuiUnlock();
        if (dialog != NO_DIALOG && !closing) {
            DrawRectangle(0, 0, w, h, Fade(BLACK, 0.25f));
            Rectangle box = {(w - 560)/2, (h - 152)/2, 560, 152};
            const char *title = text[dialog == REMOVE_DIALOG ? TXT_REMOVE : TXT_ERROR_TITLE];
            const char *message = text[dialog == REMOVE_DIALOG ? TXT_REMOVE_HINT : error_text];
            const char *buttons = text[dialog == REMOVE_DIALOG ? TXT_REMOVE_OPTIONS : TXT_OK];
            int result = GuiMessageBox(box, title, message, buttons);
            if (result >= 0) {
                if (dialog == REMOVE_DIALOG && result == 1) action = CONFIRM_REMOVE;
                dialog = NO_DIALOG;
            }
        }
        EndDrawing();
        if (closing) continue;
        if (autorun_error) {
            autorun_error = false;
            error_text = TXT_AUTORUN_ERROR;
            dialog = ERROR_DIALOG;
        }
        if (action == NEW_PROFILE && (loaded < 0 || profile_count == PROFILE_LIMIT || active >= 0)) {
            error_text = loaded < 0 ? TXT_STORE_ERROR :
                         profile_count == PROFILE_LIMIT ? TXT_LIMIT : TXT_EDIT_WHILE_ACTIVE;
            dialog = ERROR_DIALOG;
        } else if (action == REMOVE) dialog = REMOVE_DIALOG;
        else if (action == CONNECT_PROFILE) {
            if (active == selected) { ui_stop(); state = STOPPING; }
            else if (!ui_check_config(client_config_path(), profiles[selected].tag)) {
                error_text = TXT_INVALID_CFG;
                dialog = ERROR_DIALOG;
                log_open = true;
            } else if (active >= 0) {
                pending = selected;
                ui_stop();
                state = STOPPING;
            } else start_profile(selected);
        } else if (action == EDIT || action == NEW_PROFILE || action == CONFIRM_REMOVE) {
            int changed = 0, error = -1;
            XtTag keep = {0};
            if (action == CONFIRM_REMOVE) {
                int next = selected + 1 < profile_count ? selected + 1 : selected - 1;
                if (next >= 0) strcpy(keep, profiles[next].tag);
                changed = client_config_remove(&profiles[selected]);
                if (!changed) error = TXT_STORE_ERROR;
            } else {
                int creating = action == NEW_PROFILE;
                Profile edited = creating ? (Profile){0} : profiles[selected];
                if (creating) {
                    for (int n = 1; n <= PROFILE_LIMIT + 1; ++n) {
                        snprintf(edited.tag, sizeof(edited.tag), "tunnel%d", n);
                        int i = 0;
                        while (i < profile_count && strcmp(edited.tag, profiles[i].tag)) ++i;
                        if (i == profile_count) break;
                    }
                }
                int result = client_config_edit(&edited, GetWindowHandle(), text == chinese_text, creating);
                if (result < 0) error = TXT_FILE_ERROR;
                else if (result > 0) {
                    strcpy(keep, edited.tag);
                    changed = 1;
                }
            }
            if (changed) {
                loaded = client_configs_load(profiles, details);
                profile_count = loaded > 0 ? loaded : 0;
                selected = profile_count ? 0 : -1;
                for (int i = 0; i < profile_count; ++i)
                    if (!strcmp(keep, profiles[i].tag)) { selected = i; break; }
                profile_scroll = selected > 0 ? selected : 0;
                failed = -1;
                state = DISCONNECTED;
                if (loaded < 0) error = TXT_STORE_ERROR;
            }
            if (changed) {
                Font replacement = load_ui_font();
                set_font(replacement);
                release_font(font);
                font = replacement;
            }
            if (error >= 0) { error_text = error; dialog = ERROR_DIALOG; }
        }
    }
    release_font(font);
    CloseWindow();
    return 0;
}
