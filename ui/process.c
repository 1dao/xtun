#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>
#include "process.h"

static HANDLE child, control, output;

static void close_handle(HANDLE *handle) {
    if (*handle) CloseHandle(*handle);
    *handle = NULL;
}
int ui_admin(void) {
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID group;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &group)) {
        CheckTokenMembership(NULL, group, &admin);
        FreeSid(group);
    }
    return admin;
}
int ui_font_path(char *path, size_t size) {
    UINT length = GetWindowsDirectoryA(path, (UINT)size);
    static const char font[] = "\\Fonts\\segoeui.ttf";
    if (!length || length >= size || sizeof(font) > size - length) return 0;
    memcpy(path + length, font, sizeof(font));
    return 1;
}
int ui_choose_config(char *path, size_t size) {
    OPENFILENAMEA picker = {0};
    picker.lStructSize = sizeof(picker);
    picker.lpstrFilter = "XTun configuration (*.cfg)\0*.cfg\0All files\0*.*\0";
    picker.lpstrFile = path;
    picker.nMaxFile = (DWORD)size;
    picker.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameA(&picker);
}
int ui_start(const char *path, unsigned long *error) {
    char exe[MAX_PATH], command[2 * MAX_PATH + 64];
    DWORD n = GetModuleFileNameA(NULL, exe, sizeof(exe));
    char *slash = n && n < sizeof(exe) ? strrchr(exe, '\\') : NULL;
    size_t len = strlen(path);
    if (child || !slash || (size_t)(slash-exe) + sizeof("\\xtun.exe") > sizeof(exe) ||
        !len || len >= MAX_PATH || strchr(path, '"') || path[len-1] == '\\') {
        *error = ERROR_INVALID_PARAMETER;
        return 0;
    }
    strcpy(slash + 1, "xtun.exe");
    snprintf(command, sizeof(command), "\"%s\" client \"%s\" --gui-child", exe, path);
    SECURITY_ATTRIBUTES inherit = {sizeof(inherit), NULL, TRUE};
    HANDLE input = NULL, writer = NULL;
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process;
    if (!CreatePipe(&input, &control, &inherit, 0) ||
        !SetHandleInformation(control, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&output, &writer, &inherit, 0) ||
        !SetHandleInformation(output, HANDLE_FLAG_INHERIT, 0)) goto bad;
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input;
    startup.hStdOutput = startup.hStdError = writer;
    if (!CreateProcessA(exe, command, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) goto bad;
    child = process.hProcess;
    CloseHandle(process.hThread);
    close_handle(&input);
    close_handle(&writer);
    return 1;
bad:
    *error = GetLastError();
    close_handle(&input);
    close_handle(&writer);
    close_handle(&control);
    close_handle(&output);
    return 0;
}
void ui_stop(void) { close_handle(&control); }

int ui_poll(char *buffer, size_t size, unsigned long *exit_code) {
    DWORD available = 0, read = 0;
    buffer[0] = 0;
    if (!child) return 0;
    if (PeekNamedPipe(output, NULL, 0, NULL, &available, NULL) && available) {
        DWORD limit = (DWORD)(size - 1);
        if (ReadFile(output, buffer, available < limit ? available : limit, &read, NULL)) {
            buffer[read] = 0;
            return 1; /* Drain all pending output before reporting exit. */
        }
    }
    if (WaitForSingleObject(child, 0) != WAIT_OBJECT_0) return 1;
    DWORD code = 1;
    GetExitCodeProcess(child, &code);
    *exit_code = code;
    close_handle(&child);
    close_handle(&output);
    ui_stop();
    return 0;
}
