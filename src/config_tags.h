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

/* xargs has no ordered key iterator. Inspect assignment keys only, using the
 * same whitespace/comment rules, without interpreting dots in field values. */
static inline int xt_config_tags(const char *path, XtTag tags[XT_TAG_LIMIT]) {
    const char *explicit_tags = xargs_get("tags");
    if (explicit_tags) return *explicit_tags ? xt_parse_tags(explicit_tags, tags) : -1;
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    char line[4096]; int count = 0;
    while (fgets(line, sizeof(line), file)) {
        if (!strchr(line, '\n') && !feof(file)) { count = -1; break; }
        char *key = line;
        while (*key == ' ' || *key == '\t') ++key;
        if (*key == '#' || !*key) continue;
        char *end = strchr(key, '=');
        if (!end) continue;
        while (end > key && (end[-1] == ' ' || end[-1] == '\t')) --end;
        char *dot = memchr(key, '.', (size_t)(end-key));
        if (!dot) continue;
        if (dot == key || dot+1 == end || (size_t)(dot-key) >= XT_TAG_SIZE ||
            memchr(dot+1, '.', (size_t)(end-dot-1))) { count = -1; break; }
        *dot = 0;
        if (!xt_tag_valid(key)) { count = -1; break; }
        if (xt_find_tag(tags, count, key) >= 0) continue;
        if (count == XT_TAG_LIMIT) { count = -1; break; }
        strcpy(tags[count++], key);
    }
    if (ferror(file)) count = -1;
    fclose(file);
    return count;
}

static inline const char *xt_cfg_value(const char *tag, const char *field) {
    char key[96];
    if (!tag) return xargs_get(field);
    int n = snprintf(key, sizeof(key), "%s.%s", tag, field);
    return n > 0 && (size_t)n < sizeof(key) ? xargs_get(key) : NULL;
}
#endif
