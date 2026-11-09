#ifndef XTUN_UI_PROCESS_H
#define XTUN_UI_PROCESS_H
#include <stddef.h>
int ui_admin(void);
int ui_font_path(char *path, size_t size, const char *font_name);
int ui_choose_config(char *path, size_t size, int chinese);
int ui_start(const char *path, unsigned long *error);
void ui_stop(void);
int ui_poll(char *buffer, size_t size, unsigned long *exit_code);
#endif
