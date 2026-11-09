#ifndef XTUN_CONFIG_TAGS_H
#define XTUN_CONFIG_TAGS_H

#include "xargs.h"
#include <stdio.h>
#include <string.h>

enum { XT_TAG_LIMIT = 64, XT_TAG_SIZE = 32 };
typedef char XtTag[XT_TAG_SIZE];

static inline int xt_tag_valid(const char *tag) {
    size_t n = strlen(tag);
    if (!n || n >= XT_TAG_SIZE || *tag == '-') return 0;
    for (const char *p = tag; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) return 0;
    return 1;
}

static inline int xt_find_tag(const XtTag *tags, int count, const char *tag) {
    for (int i = 0; i < count; ++i)
        if (!strcmp(tags[i], tag)) return i;
    return -1;
}

static inline int xt_parse_tags(const char *value, XtTag tags[XT_TAG_LIMIT]) {
    if (!value || !*value) return 0;
    for (int i = 0; i < XT_TAG_LIMIT; ++i) {
        while (*value == ' ' || *value == '\t') ++value;
        const char *comma = strchr(value, ',');
        const char *end = comma ? comma : value + strlen(value);
        while (end > value && (end[-1] == ' ' || end[-1] == '\t')) --end;
        size_t n = (size_t)(end - value);
        if (!n || n >= XT_TAG_SIZE) return -1;
        memcpy(tags[i], value, n);
        tags[i][n] = 0;
        if (!xt_tag_valid(tags[i]) || xt_find_tag(tags, i, tags[i]) >= 0) return -1;
        if (!comma) return i + 1;
        value = comma + 1;
    }
    return -1;
}

static inline const char *xt_cfg_value(const char *tag, const char *field) {
    char key[96];
    if (!tag) return xargs_get(field);
    int n = snprintf(key, sizeof(key), "%s.%s", tag, field);
    return n > 0 && (size_t)n < sizeof(key) ? xargs_get(key) : NULL;
}
#endif
