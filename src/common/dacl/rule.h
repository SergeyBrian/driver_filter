#ifndef H_SRC_COMMON_DACL_RULE_H
#define H_SRC_COMMON_DACL_RULE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WINDEF_
typedef unsigned long DWORD;
typedef DWORD ACCESS_MASK;
typedef int BOOL;
typedef unsigned long ULONG;
#define MAX_PATH 260
#endif

typedef struct _SummarizedRule {
    char prefix[MAX_PATH];
    char sid[MAX_PATH];
    ACCESS_MASK allow;
    ACCESS_MASK deny;
} SummarizedRule, *PSummarizedRule;

SummarizedRule DecodeSummarizedRule(const void *buf);
BOOL EncodeSummarizedRule(SummarizedRule rule, void *buf, ULONG *used_len);

#ifdef __cplusplus
}  // __cplusplus
#endif

#endif  // H_SRC_COMMON_DACL_RULE_H
