#include "rule.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

SummarizedRule DecodeSummarizedRule(const void *buf) {
    SummarizedRule res = {};

    if (buf == NULL) {
        return res;
    }

    const char *ptr = (const char *)(buf);

    strncpy(res.prefix, ptr, sizeof(res.prefix));
    ptr += strlen(ptr) + 1;

    strncpy(res.username, ptr, sizeof(res.username));
    ptr += strlen(ptr) + 1;

    memcpy(&res.allow, ptr, sizeof(res.allow));
    ptr += sizeof(res.allow);

    memcpy(&res.deny, ptr, sizeof(res.deny));
    ptr += sizeof(res.deny);

    return res;
}

BOOL EncodeSummarizedRule(SummarizedRule rule, void *buf, ULONG *used_len) {
    if (buf == NULL) {
        return FALSE;
    }

    char *ptr = (char *)buf;

    ULONG s = (ULONG)strlen(rule.prefix) + 1;
    memcpy(ptr, rule.prefix, s);
    ptr += s;

    s = (ULONG)strlen(rule.username) + 1;
    memcpy(ptr, rule.username, s);
    ptr += s;

    memcpy(ptr, &rule.allow, sizeof(rule.allow));
    ptr += sizeof(rule.allow);

    memcpy(ptr, &rule.deny, sizeof(rule.deny));
    ptr += sizeof(rule.deny);

    if (used_len != NULL) {
        *used_len = (ULONG)(ptr - (char *)buf);
    }

    return TRUE;
}
