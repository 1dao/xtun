/* Windows tray/window integration adapted from xproxy's ui_backend.c. */
#include <windows.h>
#include <shellapi.h>
#include "tray.h"

#define WM_TRAYICON (WM_APP + 1)
#define TRAY_ICON_ID 1
static HWND tray_window;
static WNDPROC previous_proc;
static NOTIFYICONDATAW icon;
static UINT taskbar_created;
static int events, close_to_tray, use_chinese, icon_added;

static LRESULT CALLBACK tray_proc(HWND window, UINT message, WPARAM wp, LPARAM lp) {
    if (taskbar_created && message == taskbar_created) {
        icon_added = Shell_NotifyIconW(NIM_ADD, &icon);
        /* Never leave a hidden window unreachable after Explorer restarts. */
        if (!icon_added) ui_tray_show();
        return 0;
    }
    if (message == WM_TRAYICON) {
        if (lp == WM_LBUTTONUP || lp == WM_LBUTTONDBLCLK) events |= UI_TRAY_SHOW;
        else if (lp == WM_RBUTTONUP) {
            HMENU menu = CreatePopupMenu();
            if (!menu) return 0;
            AppendMenuW(menu, MF_STRING, UI_TRAY_SHOW, use_chinese ? L"显示窗口" : L"Show window");
            AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(menu, MF_STRING, UI_TRAY_EXIT, use_chinese ? L"退出" : L"Exit");
            POINT point;
            GetCursorPos(&point);
            SetForegroundWindow(window);
            int command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY,
                                         point.x, point.y, 0, window, NULL);
            DestroyMenu(menu);
            PostMessageW(window, WM_NULL, 0, 0);
            if (command == UI_TRAY_SHOW || command == UI_TRAY_EXIT) events |= command;
        }
        return 0;
    }
    if (message == WM_CLOSE && close_to_tray && icon_added) {
        ShowWindow(window, SW_HIDE);
        return 0;
    }
    return CallWindowProcW(previous_proc, window, message, wp, lp);
}

int ui_tray_init(void *window, int chinese) {
    if (tray_window) return 1;
    if (!window) return 0;
    tray_window = (HWND)window;
    use_chinese = chinese;
    events = close_to_tray = 0;
    taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    SetLastError(0);
    previous_proc = (WNDPROC)SetWindowLongPtrW(tray_window, GWLP_WNDPROC, (LONG_PTR)tray_proc);
    if (!previous_proc) { tray_window = NULL; return 0; }
    icon = (NOTIFYICONDATAW){0};
    icon.cbSize = sizeof(icon);
    icon.hWnd = tray_window;
    icon.uID = TRAY_ICON_ID;
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    icon.uCallbackMessage = WM_TRAYICON;
    icon.hIcon = (HICON)SendMessageW(tray_window, WM_GETICON, ICON_SMALL, 0);
    if (!icon.hIcon) icon.hIcon = LoadIconW(NULL, (LPCWSTR)IDI_APPLICATION);
    lstrcpyW(icon.szTip, L"XTun");
    icon_added = Shell_NotifyIconW(NIM_ADD, &icon);
    if (!icon_added) { ui_tray_remove(); return 0; }
    return 1;
}
void ui_tray_remove(void) {
    if (!tray_window) return;
    Shell_NotifyIconW(NIM_DELETE, &icon);
    SetWindowLongPtrW(tray_window, GWLP_WNDPROC, (LONG_PTR)previous_proc);
    tray_window = NULL;
    previous_proc = NULL;
    events = close_to_tray = icon_added = 0;
}
int ui_tray_poll(void) { int result = events; events = 0; return result; }
void ui_tray_close_to_tray(int enable) { close_to_tray = enable; }
void ui_tray_show(void) {
    if (!tray_window) return;
    ShowWindow(tray_window, SW_SHOW);
    if (IsIconic(tray_window)) ShowWindow(tray_window, SW_RESTORE);
    SetForegroundWindow(tray_window);
}
int ui_tray_visible(void) { return !tray_window || IsWindowVisible(tray_window); }
