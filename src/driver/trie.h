#ifndef H_SRC_DRIVER_TRIE_H
#define H_SRC_DRIVER_TRIE_H

#define NTDDI_VERSION NTDDI_WIN10
#include <ntifs.h>
#include <wdm.h>

#define POOL_TAG_NODE 'dNoT'  // Vertex
#define POOL_TAG_CHLD 'dHcT'  // ChildRec
#define POOL_TAG_STR 'rStT'   // strings
#define POOL_TAG_RULE 'lRuT'  // RuleRec

typedef struct _Rule {
    ACCESS_MASK mask;
} Rule, *PRule;

typedef struct _Vertex Vertex, *PVertex;

typedef struct _ChildRec {
    UNICODE_STRING Key;
    PVertex Node;
} ChildRec, *PChildRec;

typedef struct _RuleRec {
    UNICODE_STRING User;
    Rule R;
} RuleRec, *PRuleRec;

struct _Vertex {
    RTL_AVL_TABLE children;
    RTL_AVL_TABLE rules;
    BOOLEAN terminal;
};

__drv_allocatesMem(Mem) static __forceinline PVOID
    AvlAlloc(_In_ PRTL_AVL_TABLE Table, _In_ CLONG Bytes) {
    UNREFERENCED_PARAMETER(Table);
    return ExAllocatePoolWithTag(NonPagedPoolNx, (SIZE_T)Bytes, POOL_TAG_NODE);
}

static __forceinline VOID AvlFree(_In_ PRTL_AVL_TABLE Table,
                                  _In_ PVOID Buffer) {
    UNREFERENCED_PARAMETER(Table);
    ExFreePool(Buffer);
}

static RTL_GENERIC_COMPARE_RESULTS AvlCmpUStr(_In_ PRTL_AVL_TABLE Table,
                                              _In_ PVOID First,
                                              _In_ PVOID Second) {
    UNREFERENCED_PARAMETER(Table);
    const UNICODE_STRING *a = (const UNICODE_STRING *)First;
    const UNICODE_STRING *b = (const UNICODE_STRING *)Second;
    LONG r =
        RtlCompareUnicodeString((PUNICODE_STRING)a, (PUNICODE_STRING)b, TRUE);
    return (r < 0)   ? GenericLessThan
           : (r > 0) ? GenericGreaterThan
                     : GenericEqual;
}

static RTL_GENERIC_COMPARE_RESULTS AvlCmpChild(_In_ PRTL_AVL_TABLE Table,
                                               _In_ PVOID First,
                                               _In_ PVOID Second) {
    UNREFERENCED_PARAMETER(Table);
    const ChildRec *a = (const ChildRec *)First;
    const ChildRec *b = (const ChildRec *)Second;
    LONG r = RtlCompareUnicodeString((PUNICODE_STRING)&a->Key,
                                     (PUNICODE_STRING)&b->Key, TRUE);
    return (r < 0)   ? GenericLessThan
           : (r > 0) ? GenericGreaterThan
                     : GenericEqual;
}

static RTL_GENERIC_COMPARE_RESULTS AvlCmpRule(_In_ PRTL_AVL_TABLE Table,
                                              _In_ PVOID First,
                                              _In_ PVOID Second) {
    UNREFERENCED_PARAMETER(Table);
    const RuleRec *a = (const RuleRec *)First;
    const RuleRec *b = (const RuleRec *)Second;
    LONG r = RtlCompareUnicodeString((PUNICODE_STRING)&a->User,
                                     (PUNICODE_STRING)&b->User, TRUE);
    return (r < 0)   ? GenericLessThan
           : (r > 0) ? GenericGreaterThan
                     : GenericEqual;
}

_IRQL_requires_max_(APC_LEVEL) static NTSTATUS
    VertexCreate(_Outptr_ PVertex *Out) {
    *Out = NULL;
    PVertex v = (PVertex)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Vertex),
                                               POOL_TAG_NODE);
    if (!v) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(v, sizeof(*v));

    RtlInitializeGenericTableAvl(&v->children, AvlCmpChild, AvlAlloc, AvlFree,
                                 NULL);
    RtlInitializeGenericTableAvl(&v->rules, AvlCmpRule, AvlAlloc, AvlFree,
                                 NULL);
    v->terminal = FALSE;

    *Out = v;
    return STATUS_SUCCESS;
}

static VOID _FreeUnicodeStringBuffer(_Inout_ PUNICODE_STRING s) {
    if (s->Buffer) {
        ExFreePool(s->Buffer);
        s->Buffer = NULL;
        s->Length = s->MaximumLength = 0;
    }
}

_IRQL_requires_max_(APC_LEVEL) static VOID
    VertexDestroyRecursive(_In_opt_ PVertex v) {
    if (!v) return;

    PVOID restart = NULL;
    for (;;) {
        PChildRec rec = (PChildRec)RtlEnumerateGenericTableWithoutSplayingAvl(
            &v->children, &restart);
        if (!rec) break;
        PVertex child = rec->Node;
        UNICODE_STRING key = rec->Key;

        VertexDestroyRecursive(child);

        _FreeUnicodeStringBuffer(&key);

        RtlDeleteElementGenericTableAvl(&v->children, rec);

        restart = NULL;
    }

    restart = NULL;
    for (;;) {
        PRuleRec rr = (PRuleRec)RtlEnumerateGenericTableWithoutSplayingAvl(
            &v->rules, &restart);
        if (!rr) break;
        UNICODE_STRING ukey = rr->User;
        _FreeUnicodeStringBuffer(&ukey);
        RtlDeleteElementGenericTableAvl(&v->rules, rr);
        restart = NULL;
    }

    ExFreePool(v);
}

typedef struct _PT_SEG_ITER {
    UNICODE_STRING full;
    USHORT pos;
} PT_SEG_ITER;

static VOID PtSegIterInit(_Out_ PT_SEG_ITER *it, _In_ PCUNICODE_STRING path) {
    it->full = *path;
    it->pos = 0;
}

static BOOLEAN PtSegNext(_Inout_ PT_SEG_ITER *it,
                         _Out_ UNICODE_STRING *outSeg) {
    while (it->pos < it->full.Length) {
        WCHAR ch = it->full.Buffer[it->pos / 2];
        if (ch != L'\\' && ch != L'/') break;
        it->pos += sizeof(WCHAR);
    }
    if (it->pos >= it->full.Length) return FALSE;

    USHORT start = it->pos;
    while (it->pos < it->full.Length) {
        WCHAR ch = it->full.Buffer[it->pos / 2];
        if (ch == L'\\' || ch == L'/') break;
        it->pos += sizeof(WCHAR);
    }

    outSeg->Buffer = &it->full.Buffer[start / 2];
    outSeg->Length = outSeg->MaximumLength = it->pos - start;
    return TRUE;
}

static NTSTATUS DupUStrBuffer(_Out_ PUNICODE_STRING dst,
                              _In_ PCUNICODE_STRING src) {
    dst->Length = dst->MaximumLength = src->Length;
    dst->Buffer =
        (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, src->Length, POOL_TAG_STR);
    if (!dst->Buffer) {
        dst->Length = dst->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(dst->Buffer, src->Buffer, src->Length);
    return STATUS_SUCCESS;
}

static PChildRec VertexFindChild(_In_ PVertex parent,
                                 _In_ PCUNICODE_STRING seg) {
    ChildRec probe;
    probe.Key = *seg;
    probe.Node = NULL;
    return (PChildRec)RtlLookupElementGenericTableAvl(&parent->children,
                                                      &probe);
}

static NTSTATUS VertexFindOrCreateChild(_In_ PVertex parent,
                                        _In_ PCUNICODE_STRING seg,
                                        _Outptr_ PVertex *childOut) {
    *childOut = NULL;
    ChildRec probe;
    probe.Key = *seg;
    probe.Node = NULL;
    BOOLEAN newElem = FALSE;

    PChildRec rec = (PChildRec)RtlInsertElementGenericTableAvl(
        &parent->children, &probe, sizeof(ChildRec), &newElem);

    if (!rec) return STATUS_INSUFFICIENT_RESOURCES;

    if (newElem) {
        NTSTATUS st = DupUStrBuffer(&rec->Key, seg);
        if (!NT_SUCCESS(st)) {
            RtlDeleteElementGenericTableAvl(&parent->children, rec);
            return st;
        }

        st = VertexCreate(&rec->Node);
        if (!NT_SUCCESS(st)) {
            _FreeUnicodeStringBuffer(&rec->Key);
            RtlDeleteElementGenericTableAvl(&parent->children, rec);
            return st;
        }
    }
    *childOut = rec->Node;
    return STATUS_SUCCESS;
}

static NTSTATUS VertexUpsertRule(_In_ PVertex v, _In_ PCUNICODE_STRING userKey,
                                 _In_ ACCESS_MASK mask) {
    RuleRec probe;
    probe.User = *userKey;
    probe.R.mask = mask;

    BOOLEAN isNew = FALSE;
    PRuleRec rr = (PRuleRec)RtlInsertElementGenericTableAvl(
        &v->rules, &probe, sizeof(RuleRec), &isNew);
    if (!rr) return STATUS_INSUFFICIENT_RESOURCES;

    if (isNew) {
        NTSTATUS st = DupUStrBuffer(&rr->User, userKey);
        if (!NT_SUCCESS(st)) {
            RtlDeleteElementGenericTableAvl(&v->rules, rr);
            return st;
        }
    }
    rr->R.mask = mask;
    return STATUS_SUCCESS;
}

static PRuleRec VertexFindRule(_In_ PVertex v, _In_ PCUNICODE_STRING userKey) {
    RuleRec probe;
    probe.User = *userKey;
    probe.R.mask = 0;
    return (PRuleRec)RtlLookupElementGenericTableAvl(&v->rules, &probe);
}

typedef struct _Trie {
    EX_PUSH_LOCK Lock;
    PVertex Root;
} Trie, *PTrie;

_IRQL_requires_max_(APC_LEVEL) static NTSTATUS TrieCreate(_Outptr_ PTrie *Out) {
    *Out = NULL;
    PTrie t = (PTrie)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Trie),
                                           POOL_TAG_NODE);
    if (!t) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(t, sizeof(*t));
    ExInitializePushLock(&t->Lock);
    NTSTATUS st = VertexCreate(&t->Root);
    if (!NT_SUCCESS(st)) {
        ExFreePool(t);
        return st;
    }
    *Out = t;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL) static VOID TrieDestroy(_In_opt_ PTrie t) {
    if (!t) return;
    VertexDestroyRecursive(t->Root);
    ExFreePool(t);
}

_IRQL_requires_max_(APC_LEVEL) static NTSTATUS
    TrieInsertRule(_In_ PTrie trie, _In_ PCUNICODE_STRING fullPath,
                   _In_ PCUNICODE_STRING userKey, _In_ ACCESS_MASK mask) {
    if (!trie || !fullPath || !userKey) return STATUS_INVALID_PARAMETER;

    ExAcquirePushLockExclusive(&trie->Lock);
    NTSTATUS st = STATUS_SUCCESS;
    PVertex cur = trie->Root;

    PT_SEG_ITER it;
    PtSegIterInit(&it, fullPath);
    UNICODE_STRING seg;
    while (PtSegNext(&it, &seg)) {
        PVertex next = NULL;
        st = VertexFindOrCreateChild(cur, &seg, &next);
        if (!NT_SUCCESS(st)) goto out;
        cur = next;
    }
    cur->terminal = TRUE;
    st = VertexUpsertRule(cur, userKey, mask);

out:
    ExReleasePushLockExclusive(&trie->Lock);
    return st;
}

_IRQL_requires_max_(DISPATCH_LEVEL) static BOOLEAN
    TrieLookupRule(_In_ PTrie trie, _In_ PCUNICODE_STRING fullPath,
                   _In_ PCUNICODE_STRING userKey,
                   _Out_opt_ ACCESS_MASK *outMask) {
    if (outMask) *outMask = 0;
    if (!trie || !fullPath || !userKey) return FALSE;

    BOOLEAN found = FALSE;
    ACCESS_MASK acc = 0;
    ExAcquirePushLockShared(&trie->Lock);

    PVertex cur = trie->Root;
    PT_SEG_ITER it;
    PtSegIterInit(&it, fullPath);
    UNICODE_STRING seg;

    do {
        if (cur->terminal) {
            PRuleRec rr = VertexFindRule(cur, userKey);
            if (rr) {
                found = TRUE;
                acc = rr->R.mask;
            }
        }
        if (!PtSegNext(&it, &seg)) break;
        PChildRec c = VertexFindChild(cur, &seg);
        if (!c) break;
        cur = c->Node;
    } while (TRUE);

    if (cur && cur->terminal) {
        PRuleRec rr = VertexFindRule(cur, userKey);
        if (rr) {
            found = TRUE;
            acc = rr->R.mask;
        }
    }

    ExReleasePushLockShared(&trie->Lock);
    if (found && outMask) *outMask = acc;
    return found;
}

#endif  // H_SRC_DRIVER_TRIE_H
