#ifndef XTUN_UI_CLIENT_CONFIG_H
#define XTUN_UI_CLIENT_CONFIG_H

#include "config.h"

enum { PROFILE_LIMIT = XT_TAG_LIMIT, PROFILE_PATH = 260, PROFILE_NAME = 128 };
typedef struct {
    char name[PROFILE_NAME]; /* UTF-8 for rendering */
    XtTag tag;
} Profile;
typedef struct {
    char endpoint[80], address[64], peer[64];
    int full, available;
} ProfileInfo;

const char *client_config_path(void);
int client_configs_load(Profile profiles[PROFILE_LIMIT], ProfileInfo info[PROFILE_LIMIT]);
int client_config_remove(const Profile *profile);
int client_config_edit(Profile *profile, void *owner, int chinese, int creating);

#endif
