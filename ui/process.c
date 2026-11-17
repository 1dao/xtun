#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include "process.h"
#include "config.h"
#include "xtun.h"

static HANDLE child, control, output;

/* The GUI requires elevation, so Explorer's Run key cannot launch it.
 * Use an interactive, highest-privilege logon task instead. Keep the same
 * task name across upgrades so moving the executable updates its action. */
#define AUTORUN_TASK L"XTun GUI"
#define RUN_KEY L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define RUN_VALUE L"xtun-gui"

/* EncodedCommand avoids command-line quoting/injection for Unicode paths.
 * No shell window or script file is needed. The GUI is already elevated. */
static int autorun_script(const wchar_t *script) {
    static const wchar_t alphabet[] =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    wchar_t exe[MAX_PATH], command[16384];
    UINT n = GetSystemDirectoryW(exe, MAX_PATH);
    if (!n || n + 48 >= MAX_PATH) return 0;
    wcscat(exe, L"\\WindowsPowerShell\\v1.0\\powershell.exe");
    int prefix = swprintf(command, sizeof(command)/sizeof(*command),
                         L"\"%ls\" -NoLogo -NoProfile -NonInteractive -EncodedCommand ", exe);
    size_t bytes = wcslen(script) * sizeof(wchar_t);
    size_t encoded = ((bytes + 2) / 3) * 4;
    if (prefix < 0 || prefix + encoded + 1 > sizeof(command)/sizeof(*command)) return 0;
    const unsigned char *data = (const unsigned char *)script;
    wchar_t *out = command + prefix;
    for (size_t i = 0; i < bytes; i += 3) {
        unsigned v = (unsigned)data[i] << 16;
        if (i + 1 < bytes) v |= (unsigned)data[i + 1] << 8;
        if (i + 2 < bytes) v |= data[i + 2];
        *out++ = alphabet[(v >> 18) & 63];
        *out++ = alphabet[(v >> 12) & 63];
        *out++ = i + 1 < bytes ? alphabet[(v >> 6) & 63] : L'=';
        *out++ = i + 2 < bytes ? alphabet[v & 63] : L'=';
    }
    *out = 0;
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process;
    if (!CreateProcessW(exe, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) return 0;
    CloseHandle(process.hThread);
    DWORD code = 1;
    /* Wait for completion: a failed registration must not check the box. */
    DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    int ok = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &code) && code == 0;
    CloseHandle(process.hProcess);
    return ok;
}

/* Escape a PowerShell single-quoted literal (including embedded apostrophes). */
static void autorun_literal(wchar_t *out, const wchar_t *value) {
    *out++ = L'\'';
    while (*value) {
        if (*value == L'\'') *out++ = L'\'';
        *out++ = *value++;
    }
    *out++ = L'\'';
    *out = 0;
}

int ui_get_autorun(void) {
    return autorun_script(
        L"$ErrorActionPreference='Stop'; try {"
        L"$t=Get-ScheduledTask -TaskPath '\\' -TaskName '" AUTORUN_TASK L"';"
        L"if ($t.Settings.Enabled -and $t.Principal.RunLevel -eq 'Highest' "
        L"-and $t.Principal.LogonType -eq 'Interactive' "
        L"-and @($t.Triggers | Where-Object {$_.Enabled}).Count -gt 0) {exit 0};"
        L"exit 1 } catch {exit 1}");
}
int ui_set_autorun(int enable) {
    wchar_t script[4096];
    if (enable) {
        wchar_t exe[MAX_PATH], directory[MAX_PATH];
        wchar_t exe_literal[MAX_PATH * 2 + 3], dir_literal[MAX_PATH * 2 + 3];
        DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
        DWORD d = GetCurrentDirectoryW(MAX_PATH, directory);
        if (!n || n >= MAX_PATH || !d || d >= MAX_PATH) return 0;
        autorun_literal(exe_literal, exe);
        autorun_literal(dir_literal, directory);
        int length = swprintf(script, sizeof(script)/sizeof(*script),
            L"$ErrorActionPreference='Stop'; try {"
            L"$exe=%ls; $dir=%ls;"
            L"$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name;"
            L"$a=New-ScheduledTaskAction -Execute $exe "
            L"-Argument ('--autostart '+[char]34+$dir+'\\.'+[char]34) -WorkingDirectory $dir;"
            L"$t=New-ScheduledTaskTrigger -AtLogOn -User $user;"
            L"$p=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest;"
            L"$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
            L"-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew;"
            L"Register-ScheduledTask -TaskPath '\\' -TaskName '" AUTORUN_TASK L"' "
            L"-Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null;"
            L"exit 0 } catch {exit 1}", exe_literal, dir_literal);
        if (length < 0 || length >= sizeof(script)/sizeof(*script)) return 0;
    } else {
        wcscpy(script,
            L"$ErrorActionPreference='Stop'; try {"
            L"$t=Get-ScheduledTask -TaskPath '\\' | Where-Object {$_.TaskName -eq '" AUTORUN_TASK L"'};"
            L"if ($t) {$t | Unregister-ScheduledTask -Confirm:$false};"
            L"exit 0 } catch {exit 1}");
    }
    if (!autorun_script(script)) return 0;
    /* Remove the legacy entry only after the task operation succeeds. */
    HKEY key;
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_SET_VALUE, &key);
    if (result == ERROR_FILE_NOT_FOUND) return 1;
    if (result != ERROR_SUCCESS) return 0;
    result = RegDeleteValueW(key, RUN_VALUE);
    RegCloseKey(key);
    return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
}
int ui_autorun_workdir(void) {
    int count = 0;
    wchar_t **args = CommandLineToArgvW(GetCommandLineW(), &count);
    int ok = args && count == 3 && !wcscmp(args[1], L"--autostart") &&
             SetCurrentDirectoryW(args[2]);
    if (args) LocalFree(args);
    return ok;
}

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
int ui_font_path(char *path, size_t size, const char *font_name) {
    UINT length = GetWindowsDirectoryA(path, (UINT)size);
    if (!length || length >= size) return 0;
    int written = snprintf(path + length, size - length, "\\Fonts\\%s", font_name);
    return written > 0 && (size_t)written < size - length;
}
int ui_check_config(const char *path, const char *tag) {
    XtConfig config = {0};
    int ok = xt_load_config(&config, path, tag);
    SecureZeroMemory(config.key, sizeof(config.key));
    return ok;
}
int ui_start(const char *tag, unsigned long *error) {
    char exe[MAX_PATH], command[MAX_PATH + 96];
    DWORD n = GetModuleFileNameA(NULL, exe, MAX_PATH);
    if (child || !xt_tag_valid(tag) || !n || n >= MAX_PATH) {
        *error = ERROR_INVALID_PARAMETER;
        return 0;
    }
    /* The GUI embeds the same entry point as the standalone console program.
     * Keep pipe-based shutdown/logging and run it in a hidden copy of ourselves. */
    snprintf(command, sizeof(command), "\"%s\" --tunnel-worker client --tag %s --gui-child", exe, tag);
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
