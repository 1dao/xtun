#ifndef XTUN_UI_PROCESS_H
#define XTUN_UI_PROCESS_H
#include <stddef.h>
int ui_admin(void);
int ui_get_autorun(void);
int ui_set_autorun(int enable);
int ui_autorun_workdir(void);
int ui_font_path(char *path, size_t size, const char *font_name);
int ui_start(const char *tag, unsigned long *error);
int ui_check_config(const char *path, const char *tag);
void ui_stop(void);
int ui_poll(char *buffer, size_t size, unsigned long *exit_code);
#endif
