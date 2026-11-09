#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "client_config.h"
#include "process.h"
#include "xtun.h"

static char config_path[PROFILE_PATH];

const char *client_config_path(void) { return config_path; }

static int init_path(void) {
    DWORD n = GetFullPathNameA(XT_CLIENT_CONFIG, sizeof(config_path), config_path, NULL);
    return n > 0 && n < sizeof(config_path);
}

/* Return the file's ordered tag list without retaining xargs state. */
static int load_tags(XtTag tags[XT_TAG_LIMIT]) {
    if (xargs_load_config(config_path)) {
        DWORD attributes = GetFileAttributesA(config_path);
        return attributes == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND ? 0 : -1;
    }
    const char *value = xargs_get("tags");
    int count = value ? xt_parse_tags(value, tags) : -1;
    xargs_cleanup();
    return count;
}

int client_configs_load(Profile profiles[PROFILE_LIMIT], ProfileInfo info[PROFILE_LIMIT]) {
    if (!init_path()) return -1;
    XtTag tags[XT_TAG_LIMIT];
    int count = load_tags(tags);
    if (count <= 0) return count;
    if (xargs_load_config(config_path)) return -1;
    for (int i = 0; i < count; ++i) {
        const char *tag = tags[i];
        strcpy(profiles[i].tag, tag);
        const char *label = xt_cfg_value(tag, "label");
        if (!label || !*label || strlen(label) >= PROFILE_NAME ||
            !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, label, -1, NULL, 0)) label = tag;
        strcpy(profiles[i].name, label);

        const char *host = xt_cfg_value(tag, "endpoint"), *port = xt_cfg_value(tag, "port");
        const char *address = xt_cfg_value(tag, "address"), *peer = xt_cfg_value(tag, "peer_address");
        const char *full = xt_cfg_value(tag, "full_tunnel");
        memset(&info[i], 0, sizeof(info[i]));
        if (host && *host)
            snprintf(info[i].endpoint, sizeof(info[i].endpoint), "%s:%s", host, port ? port : "51215");
        if (address) snprintf(info[i].address, sizeof(info[i].address), "%s", address);
        if (peer) snprintf(info[i].peer, sizeof(info[i].peer), "%s", peer);
        info[i].full = full && (!strcmp(full, "true") || !strcmp(full, "1"));
        info[i].available = host && *host;
    }
    xargs_cleanup();
    return count;
}

static const char *assignment(const char *line, size_t *length) {
    while (*line == ' ' || *line == '\t') ++line;
    if (*line == '#' || !*line) return NULL;
    const char *end = strchr(line, '=');
    if (!end) return NULL;
    while (end > line && (end[-1] == ' ' || end[-1] == '\t')) --end;
    if (end == line) return NULL;
    *length = (size_t)(end - line);
    return line;
}
static int matches_tag(const char *key, size_t length, const char *tag) {
    size_t prefix = strlen(tag);
    return length > prefix && key[prefix] == '.' && !memcmp(key, tag, prefix);
}

static int write_tag_fields(FILE *file, const Profile *profile, char *body) {
    if (fprintf(file, "\n%s.label=%s\n", profile->tag, profile->name) < 0) return 0;
    while (*body) {
        char *next = strchr(body, '\n');
        if (next) *next++ = 0;
        size_t length = strlen(body);
        if (length && body[length - 1] == '\r') body[length - 1] = 0;
        while (*body == ' ' || *body == '\t') ++body;
        if (*body == '#' || !*body) {
            if (*body && fprintf(file, "%s\n", body) < 0) return 0;
        } else {
            size_t key_length;
            const char *key = assignment(body, &key_length);
            if (!key || key_length > 64 || (key_length == 5 && !memcmp(key, "label", 5))) return 0;
            for (size_t i = 0; i < key_length; ++i)
                if (!((key[i] >= 'a' && key[i] <= 'z') || key[i] == '_' ||
                      (key[i] >= '0' && key[i] <= '9'))) return 0;
            if (strlen(body) + strlen(profile->tag) + 2 >= 4096 ||
                fprintf(file, "%s.%s\n", profile->tag, body) < 0) return 0;
        }
        if (!next) break;
        body = next;
    }
    return 1;
}

/* Rewrite just the tag list and one section, then validate before replacing. */
static int update_config(const Profile *profile, char *body, int creating) {
    XtTag tags[XT_TAG_LIMIT];
    int count = load_tags(tags);
    if (count < 0) return 0;
    int index = xt_find_tag(tags, count, profile->tag);
    if (creating ? (index >= 0 || count == XT_TAG_LIMIT) : index < 0) return 0;
    if (creating) strcpy(tags[count++], profile->tag);

    char directory[PROFILE_PATH], temp[PROFILE_PATH];
    strcpy(directory, config_path);
    char *slash = strrchr(directory, '\\');
    if (!slash) return 0;
    *slash = 0;
    if (!GetTempFileNameA(directory, "xtc", 0, temp)) return 0;
    FILE *source = fopen(config_path, "rb");
    FILE *target = fopen(temp, "wb");
    int ok = target && (source || creating);
    if (ok) ok = fputs("tags=", target) >= 0;
    int written = 0;
    for (int i = 0; i < count && ok; ++i) {
        if (!body && i == index) continue;
        ok = fprintf(target, "%s%s", written++ ? "," : "", tags[i]) >= 0;
    }
    if (ok) ok = fputc('\n', target) != EOF;
    char line[4096];
    while (ok && source && fgets(line, sizeof(line), source)) {
        if (!strchr(line, '\n') && !feof(source)) { ok = 0; break; }
        size_t length;
        const char *key = assignment(line, &length);
        if (key && ((length == 4 && !memcmp(key, "tags", 4)) ||
                    matches_tag(key, length, profile->tag))) continue;
        ok = fputs(line, target) >= 0;
    }
    if (source) {
        if (ferror(source)) ok = 0;
        fclose(source);
    }
    if (ok && body) ok = write_tag_fields(target, profile, body);
    if (target && fclose(target)) ok = 0;
    if (ok && body) ok = ui_check_config(temp, profile->tag);
    if (ok) ok = MoveFileExA(temp, config_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    if (!ok) DeleteFileA(temp);
    return ok;
}
int client_config_remove(const Profile *profile) { return update_config(profile, NULL, 0); }

enum { CFG_LIMIT = 16384, NAME_FIELD = 100, CFG_FIELD = 101, TAG_FIELD = 102 };
typedef struct {
    Profile *profile;
    HWND name, tag, cfg;
    WCHAR source[CFG_LIMIT];
    int chinese, saved, creating;
} Editor;

static const WCHAR *label(Editor *editor, const WCHAR *zh, const WCHAR *en) {
    return editor->chinese ? zh : en;
}
static int editor_read(Editor *editor) {
    if (editor->creating) {
        wcscpy(editor->source, L"endpoint=\r\nport=51215\r\nidentity=client-1\r\n"
                               L"name=xtun0\r\naddress=10.77.0.2\r\npeer_address=10.77.0.1\r\n");
        return 1;
    }
    FILE *file = fopen(config_path, "rb");
    if (!file) return 0;
    char line[4096], body[CFG_LIMIT];
    size_t used = 0, prefix = strlen(editor->profile->tag) + 1;
    int ok = 1;
    while (fgets(line, sizeof(line), file)) {
        if (!strchr(line, '\n') && !feof(file)) { ok = 0; break; }
        size_t length;
        const char *key = assignment(line, &length);
        if (!key || !matches_tag(key, length, editor->profile->tag) ||
            (length - prefix == 5 && !memcmp(key + prefix, "label", 5))) continue;
        const char *field = key + prefix;
        size_t n = strlen(field);
        while (n && (field[n - 1] == '\r' || field[n - 1] == '\n')) --n;
        if (used + n + 2 >= sizeof(body)) { ok = 0; break; }
        memcpy(body + used, field, n);
        used += n;
        body[used++] = '\r';
        body[used++] = '\n';
    }
    if (ferror(file)) ok = 0;
    fclose(file);
    body[used] = 0;
    return ok && MultiByteToWideChar(CP_ACP, 0, body, -1, editor->source, CFG_LIMIT) != 0;
}
static int editor_save(Editor *editor) {
    Profile updated = *editor->profile;
    WCHAR name[PROFILE_NAME], tag[XT_TAG_SIZE];
    GetWindowTextW(editor->name, name, PROFILE_NAME);
    GetWindowTextW(editor->tag, tag, XT_TAG_SIZE);
    if (!name[0] || wcspbrk(name, L"#\r\n") ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, updated.name, PROFILE_NAME, NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, tag, -1, updated.tag, XT_TAG_SIZE, NULL, NULL) ||
        !xt_tag_valid(updated.tag)) return 0;
    GetWindowTextW(editor->cfg, editor->source, CFG_LIMIT);
    char content[CFG_LIMIT];
    BOOL substituted = FALSE;
    int utf8 = GetACP() == CP_UTF8;
    int bytes = WideCharToMultiByte(CP_ACP, utf8 ? 0 : WC_NO_BEST_FIT_CHARS,
                                    editor->source, -1, content, sizeof(content), NULL,
                                    utf8 ? NULL : &substituted);
    if (bytes < 2 || substituted || !update_config(&updated, content, editor->creating)) return 0;
    *editor->profile = updated;
    return 1;
}
static HWND control(HWND window, const WCHAR *kind, const WCHAR *caption, DWORD style,
                    DWORD ex_style, int id, int x, int y, int width, int height) {
    HWND child = CreateWindowExW(ex_style, kind, caption, WS_CHILD | WS_VISIBLE | style,
                                 x, y, width, height, window, (HMENU)(INT_PTR)id,
                                 GetModuleHandleW(NULL), NULL);
    SendMessageW(child, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    return child;
}
static LRESULT CALLBACK editor_proc(HWND window, UINT msg, WPARAM wp, LPARAM lp) {
    Editor *editor = (Editor *)GetWindowLongPtrW(window, GWLP_USERDATA);
    if (msg == WM_CREATE) {
        editor = ((CREATESTRUCTW *)lp)->lpCreateParams;
        SetWindowLongPtrW(window, GWLP_USERDATA, (LONG_PTR)editor);
        WCHAR name[PROFILE_NAME] = {0};
        MultiByteToWideChar(CP_UTF8, 0, editor->profile->name, -1, name, PROFILE_NAME);
        control(window, L"STATIC", label(editor, L"配置名称", L"Profile name"), 0, 0, 0, 16, 14, 355, 20);
        control(window, L"STATIC", label(editor, L"配置标签（Tag）", L"Configuration tag"), 0, 0, 0, 389, 14, 207, 20);
        editor->name = control(window, L"EDIT", name, WS_TABSTOP | ES_AUTOHSCROLL,
                               WS_EX_CLIENTEDGE, NAME_FIELD, 16, 36, 355, 25);
        WCHAR tag[XT_TAG_SIZE] = {0};
        MultiByteToWideChar(CP_UTF8, 0, editor->profile->tag, -1, tag, XT_TAG_SIZE);
        editor->tag = control(window, L"EDIT", tag, WS_TABSTOP | ES_AUTOHSCROLL |
                              (editor->creating ? 0 : ES_READONLY),
                              WS_EX_CLIENTEDGE, TAG_FIELD, 389, 36, 207, 25);
        SendMessageW(editor->tag, EM_SETLIMITTEXT, XT_TAG_SIZE - 1, 0);
        SendMessageW(editor->name, EM_SETLIMITTEXT, 40, 0);
        control(window, L"STATIC", label(editor, L"客户端配置（CFG）。可设置 psk，或沿用全局密钥。",
                 L"Client configuration (CFG). Set psk or inherit the shared key."),
                0, 0, 0, 16, 73, 580, 20);
        editor->cfg = control(window, L"EDIT", editor->source,
                              WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
                              WS_EX_CLIENTEDGE, CFG_FIELD, 16, 96, 580, 252);
        SendMessageW(editor->cfg, EM_SETLIMITTEXT, CFG_LIMIT - 1, 0);
        control(window, L"BUTTON", label(editor, L"保存", L"Save"),
                WS_TABSTOP | BS_DEFPUSHBUTTON, 0, IDOK, 412, 363, 88, 29);
        control(window, L"BUTTON", label(editor, L"取消", L"Cancel"),
                WS_TABSTOP | BS_PUSHBUTTON, 0, IDCANCEL, 508, 363, 88, 29);
        return editor->name && editor->tag && editor->cfg ? 0 : -1;
    }
    if (msg == WM_COMMAND && LOWORD(wp) == IDOK) {
        if (editor_save(editor)) { editor->saved = 1; DestroyWindow(window); }
        else MessageBoxW(window, label(editor, L"无法保存。请检查配置名称、标签、CFG 字段和密钥。",
                         L"Could not save. Check the name, tag, CFG fields, and PSK."),
                         L"XTun", MB_OK | MB_ICONWARNING);
        return 0;
    }
    if (msg == WM_CLOSE || (msg == WM_COMMAND && LOWORD(wp) == IDCANCEL)) {
        DestroyWindow(window);
        return 0;
    }
    return DefWindowProcW(window, msg, wp, lp);
}
int client_config_edit(Profile *profile, void *owner, int chinese, int creating) {
    Editor editor = {.profile = profile, .chinese = chinese, .creating = creating};
    if (!editor_read(&editor)) return -1;
    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSW cls = {.lpfnWndProc = editor_proc, .hInstance = instance,
        .hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512)),
        .hbrBackground = (HBRUSH)(COLOR_WINDOW + 1), .lpszClassName = L"XTunProfileEditor"};
    if (!RegisterClassW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return -1;
    DWORD style = WS_CAPTION | WS_SYSMENU;
    RECT bounds = {0, 0, 612, 407}, parent = {0};
    AdjustWindowRectEx(&bounds, style, FALSE, WS_EX_DLGMODALFRAME);
    int width = bounds.right - bounds.left, height = bounds.bottom - bounds.top;
    GetWindowRect((HWND)owner, &parent);
    HWND window = CreateWindowExW(WS_EX_DLGMODALFRAME, cls.lpszClassName,
        label(&editor, L"XTun 配置编辑", L"XTun profile editor"), style,
        (parent.left + parent.right - width) / 2, (parent.top + parent.bottom - height) / 2,
        width, height, (HWND)owner, NULL, instance, &editor);
    if (!window) return -1;
    EnableWindow((HWND)owner, FALSE);
    ShowWindow(window, SW_SHOW);
    SetFocus(editor.name);
    MSG msg;
    while (IsWindow(window)) {
        int result = GetMessageW(&msg, NULL, 0, 0);
        if (result <= 0) {
            if (!result) PostQuitMessage((int)msg.wParam);
            DestroyWindow(window);
            break;
        }
        if (!IsDialogMessageW(window, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow((HWND)owner, TRUE);
    SetActiveWindow((HWND)owner);
    return editor.saved;
}
