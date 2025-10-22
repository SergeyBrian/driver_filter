#ifndef H_SRC_DRIVER_TRIE_H
#define H_SRC_DRIVER_TRIE_H

#define NTDDI_VERSION NTDDI_WIN10
#include <ntifs.h>
#include <wdm.h>

#define POOL_TAG_NODE 'dNoT'  // Vertex
#define POOL_TAG_CHLD 'dHcT'  // ChildRec
#define POOL_TAG_STR 'rStT'   // strings
#define POOL_TAG_RULE 'lRuT'  // RuleRec

#define CACHE_PATH \
    L"\\??\\C:\\ProgramData\\DriverFilterSvc\\db\\driver-cache.bin"

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

static __forceinline BOOLEAN _HasChildren(_In_ PVertex v) {
    return !RtlIsGenericTableEmptyAvl(&v->children);
}
static __forceinline BOOLEAN _HasRules(_In_ PVertex v) {
    return !RtlIsGenericTableEmptyAvl(&v->rules);
}

static NTSTATUS VertexDeleteRule(_In_ PVertex v,
                                 _In_ PCUNICODE_STRING userKey) {
    if (!v || !userKey) return STATUS_INVALID_PARAMETER;

    RuleRec probe;
    probe.User = *userKey;
    probe.R.mask = 0;
    PRuleRec rr = (PRuleRec)RtlLookupElementGenericTableAvl(&v->rules, &probe);
    if (!rr) return STATUS_NOT_FOUND;

    _FreeUnicodeStringBuffer(&rr->User);
    RtlDeleteElementGenericTableAvl(&v->rules, rr);

    if (!_HasRules(v)) v->terminal = FALSE;

    return STATUS_SUCCESS;
}

NTSTATUS TrieDeleteRule(_In_ PTrie trie, _In_ PCUNICODE_STRING fullPath,
                        _In_ PCUNICODE_STRING userKey) {
    if (!trie || !fullPath || !userKey) return STATUS_INVALID_PARAMETER;

    enum { MAX_SEGS = 256 };
    PVertex pathVerts[MAX_SEGS];
    UNICODE_STRING pathSegs[MAX_SEGS];
    ULONG depth = 0;

    ExAcquirePushLockExclusive(&trie->Lock);

    PVertex cur = trie->Root;
    pathVerts[depth++] = cur;

    PT_SEG_ITER it;
    PtSegIterInit(&it, fullPath);
    UNICODE_STRING seg;
    while (PtSegNext(&it, &seg)) {
        if (depth >= MAX_SEGS) {
            ExReleasePushLockExclusive(&trie->Lock);
            return STATUS_NAME_TOO_LONG;
        }
        PChildRec c = VertexFindChild(cur, &seg);
        if (!c) {
            ExReleasePushLockExclusive(&trie->Lock);
            return STATUS_NOT_FOUND;
        }
        pathSegs[depth - 1] = seg;
        cur = c->Node;
        pathVerts[depth++] = cur;
    }

    NTSTATUS st = VertexDeleteRule(cur, userKey);
    if (!NT_SUCCESS(st)) {
        ExReleasePushLockExclusive(&trie->Lock);
        return st;
    }

    while (depth > 1) {
        PVertex leaf = pathVerts[depth - 1];
        if (_HasChildren(leaf) || _HasRules(leaf) || leaf->terminal) break;

        PVertex parent = pathVerts[depth - 2];
        UNICODE_STRING segToLeaf = pathSegs[depth - 2];

        PChildRec childRec = VertexFindChild(parent, &segToLeaf);
        if (!childRec || childRec->Node != leaf) {
            break;
        }

        _FreeUnicodeStringBuffer(&childRec->Key);
        RtlDeleteElementGenericTableAvl(&parent->children, childRec);

        ExFreePool(leaf);

        depth--;
    }

    ExReleasePushLockExclusive(&trie->Lock);
    return STATUS_SUCCESS;
}

// Export import

static NTSTATUS WriteAt(HANDLE h, ULONGLONG *off, const void *buf, ULONG len) {
    IO_STATUS_BLOCK ios = {0};
    LARGE_INTEGER o;
    o.QuadPart = (LONGLONG)(*off);
    NTSTATUS st =
        ZwWriteFile(h, NULL, NULL, NULL, &ios, (PVOID)buf, len, &o, NULL);
    if (NT_SUCCESS(st)) *off += len;
    return st;
}
static NTSTATUS ReadAt(HANDLE h, ULONGLONG *off, void *buf, ULONG len) {
    IO_STATUS_BLOCK ios = {0};
    LARGE_INTEGER o;
    o.QuadPart = (LONGLONG)(*off);
    NTSTATUS st = ZwReadFile(h, NULL, NULL, NULL, &ios, buf, len, &o, NULL);
    if (NT_SUCCESS(st)) *off += len;
    return st;
}

static ULONG CountRules(_In_ PVertex v) {
    ULONG c = 0;
    PVOID it = NULL;
    while (RtlEnumerateGenericTableWithoutSplayingAvl(&v->rules, &it)) ++c;
    return c;
}
static ULONG CountChildren(_In_ PVertex v) {
    ULONG c = 0;
    PVOID it = NULL;
    while (RtlEnumerateGenericTableWithoutSplayingAvl(&v->children, &it)) ++c;
    return c;
}

static NTSTATUS WriteVertex(HANDLE h, ULONGLONG *off, _In_ PVertex v) {
    NTSTATUS st;
    UCHAR term = v->terminal ? 1 : 0;
    ULONG rc = CountRules(v);
    ULONG cc = CountChildren(v);

    st = WriteAt(h, off, &term, sizeof(term));
    if (!NT_SUCCESS(st)) return st;
    st = WriteAt(h, off, &rc, sizeof(rc));
    if (!NT_SUCCESS(st)) return st;
    st = WriteAt(h, off, &cc, sizeof(cc));
    if (!NT_SUCCESS(st)) return st;

    PVOID it = NULL;
    for (;;) {
        PRuleRec rr = (PRuleRec)RtlEnumerateGenericTableWithoutSplayingAvl(
            &v->rules, &it);
        if (!rr) break;
        USHORT ulen = rr->User.Length;
        st = WriteAt(h, off, &ulen, sizeof(ulen));
        if (!NT_SUCCESS(st)) return st;
        st = WriteAt(h, off, rr->User.Buffer, ulen);
        if (!NT_SUCCESS(st)) return st;
        st = WriteAt(h, off, &rr->R.mask, sizeof(rr->R.mask));
        if (!NT_SUCCESS(st)) return st;
    }

    it = NULL;
    for (;;) {
        PChildRec cr = (PChildRec)RtlEnumerateGenericTableWithoutSplayingAvl(
            &v->children, &it);
        if (!cr) break;
        USHORT klen = cr->Key.Length;
        st = WriteAt(h, off, &klen, sizeof(klen));
        if (!NT_SUCCESS(st)) return st;
        st = WriteAt(h, off, cr->Key.Buffer, klen);
        if (!NT_SUCCESS(st)) return st;
        st = WriteVertex(h, off, cr->Node);
        if (!NT_SUCCESS(st)) return st;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ReadVertex(HANDLE h, ULONGLONG *off, _Inout_ PVertex parent) {
    NTSTATUS st;
    UCHAR term = 0;
    ULONG rc = 0, cc = 0;

    st = ReadAt(h, off, &term, sizeof(term));
    if (!NT_SUCCESS(st)) return st;
    st = ReadAt(h, off, &rc, sizeof(rc));
    if (!NT_SUCCESS(st)) return st;
    st = ReadAt(h, off, &cc, sizeof(cc));
    if (!NT_SUCCESS(st)) return st;

    parent->terminal = (term != 0);

    for (ULONG i = 0; i < rc; ++i) {
        USHORT ulen = 0;
        st = ReadAt(h, off, &ulen, sizeof(ulen));
        if (!NT_SUCCESS(st)) return st;
        UNICODE_STRING usr = {0};
        usr.Length = usr.MaximumLength = ulen;
        usr.Buffer =
            (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, ulen, POOL_TAG_STR);
        if (!usr.Buffer) return STATUS_INSUFFICIENT_RESOURCES;
        st = ReadAt(h, off, usr.Buffer, ulen);
        if (!NT_SUCCESS(st)) {
            ExFreePool(usr.Buffer);
            return st;
        }
        ULONG mask = 0;
        st = ReadAt(h, off, &mask, sizeof(mask));
        if (!NT_SUCCESS(st)) {
            ExFreePool(usr.Buffer);
            return st;
        }
        st = VertexUpsertRule(parent, &usr, (ACCESS_MASK)mask);
        ExFreePool(usr.Buffer);
        if (!NT_SUCCESS(st)) return st;
    }

    for (ULONG i = 0; i < cc; ++i) {
        USHORT klen = 0;
        st = ReadAt(h, off, &klen, sizeof(klen));
        if (!NT_SUCCESS(st)) return st;
        UNICODE_STRING key = {0};
        key.Length = key.MaximumLength = klen;
        key.Buffer =
            (PWCH)ExAllocatePoolWithTag(NonPagedPoolNx, klen, POOL_TAG_STR);
        if (!key.Buffer) return STATUS_INSUFFICIENT_RESOURCES;
        st = ReadAt(h, off, key.Buffer, klen);
        if (!NT_SUCCESS(st)) {
            ExFreePool(key.Buffer);
            return st;
        }

        PVertex child = NULL;
        st = VertexFindOrCreateChild(parent, &key, &child);
        ExFreePool(key.Buffer);
        if (!NT_SUCCESS(st)) return st;

        st = ReadVertex(h, off, child);
        if (!NT_SUCCESS(st)) return st;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS TrieSaveToCacheFile(_In_ PTrie trie) {
    if (!trie) return STATUS_INVALID_PARAMETER;

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, CACHE_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(
        &oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK ios = {0};
    NTSTATUS st = ZwCreateFile(
        &h, GENERIC_WRITE | SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    ULONGLONG off = 0;
    ExAcquirePushLockShared(&trie->Lock);
    st = WriteVertex(h, &off, trie->Root);
    ExReleasePushLockShared(&trie->Lock);

    ZwClose(h);
    return st;
}

_IRQL_requires_(PASSIVE_LEVEL) NTSTATUS
    TrieInitFromCacheFile(_Inout_ PTrie trie) {
    if (!trie) return STATUS_INVALID_PARAMETER;

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, CACHE_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(
        &oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK ios = {0};
    NTSTATUS st = ZwCreateFile(
        &h, GENERIC_READ | SYNCHRONIZE, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    PVertex newRoot = NULL;
    st = VertexCreate(&newRoot);
    if (!NT_SUCCESS(st)) {
        ZwClose(h);
        return st;
    }

    ULONGLONG off = 0;
    st = ReadVertex(h, &off, newRoot);
    ZwClose(h);
    if (!NT_SUCCESS(st)) {
        VertexDestroyRecursive(newRoot);
        return st;
    }

    ExAcquirePushLockExclusive(&trie->Lock);
    PVertex old = trie->Root;
    trie->Root = newRoot;
    ExReleasePushLockExclusive(&trie->Lock);

    VertexDestroyRecursive(old);
    return STATUS_SUCCESS;
}

#endif  // H_SRC_DRIVER_TRIE_H
