#ifndef XTUN_UI_TRAY_H
#define XTUN_UI_TRAY_H

enum { UI_TRAY_SHOW = 1, UI_TRAY_EXIT = 2 };
int ui_tray_init(void *window, int chinese);
void ui_tray_remove(void);
int ui_tray_poll(void);
void ui_tray_close_to_tray(int enable);
void ui_tray_show(void);
int ui_tray_visible(void);

#endif
