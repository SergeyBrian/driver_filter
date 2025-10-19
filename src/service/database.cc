#include "database.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <shlobj.h>

#include <format>
#include <filesystem>

#include <sqlite3.h>

#include "service/log.h"
#include "common/dacl/internal.h"
#include "utils/strconv.h"

namespace database {
static sqlite3 *db{};

static std::wstring GetKnownFolder(REFKNOWNFOLDERID id) {
    PWSTR p = nullptr;
    if (SHGetKnownFolderPath(id, 0, nullptr, &p) != S_OK) return L"";
    std::wstring s = p;
    CoTaskMemFree(p);
    return s;
}

static bool EnsureDir(const std::wstring &dir) {
    std::error_code ec;
    if (std::filesystem::exists(dir, ec)) return true;
    if (!std::filesystem::create_directories(dir, ec)) {
        logA("[ERR] create_directories('%s') failed: %d",
             utils::strconv::to_utf8(dir.c_str()).c_str(), int(ec.value()));
        return false;
    }
    return true;
}

static std::wstring BuildDbPath() {
    std::wstring base = GetKnownFolder(FOLDERID_ProgramData);
    if (base.empty()) {
        logA("[ERR] SHGetKnownFolderPath(FOLDERID_ProgramData) failed");
        return {};
    }

    std::filesystem::path dir = std::filesystem::path(base) /
                                dacl::proto::internal::ServiceName / L"db";

    if (!EnsureDir(dir.wstring())) return L"";

    return (dir / L"config.db").wstring();
}

bool Connect() {
    std::wstring dbw = BuildDbPath();
    if (dbw.empty()) return false;

    std::string dbu8 = utils::strconv::to_utf8(dbw.c_str());
    int rc = sqlite3_open(dbu8.c_str(), &db);
    if (rc) {
        logA("[ERR] sqlite3_open('%s') failed: %d", dbu8.c_str(), rc);
        return false;
    }
    logA("[INFO] DB opened at %s", dbu8.c_str());

    char *err{};
    constexpr const char *init_q = R"(CREATE TABLE IF NOT EXISTS rules(
                path TEXT PRIMARY KEY,
                user TEXT,
                type INTEGER,
                access_mask INTEGER
            ))";
    if (sqlite3_exec(db, init_q, nullptr, nullptr, &err)) {
        logA("[ERROR] Can't initialize database: %s", err);
        sqlite3_free(err);
        return false;
    }

    return true;
}

void Disconnect() { sqlite3_close(db); }

bool InsertRule(const dacl::Rule &rule) {
    if (db == nullptr) {
        logA("[ERROR] Database not connected");
        return false;
    }

    constexpr const char *q =
        R"(INSERT INTO rules (path, user, type, access_mask) VALUES (?, ?, ?, ?);)";

    sqlite3_stmt *stmt{};
    if (sqlite3_prepare_v2(db, q, -1, &stmt, nullptr)) {
        logA("[ERROR] InsertRule failed: can't prepare");
        return false;
    }

    sqlite3_bind_text(stmt, 1, rule.path.c_str(), -1, nullptr);
    sqlite3_bind_text(stmt, 2, rule.user.c_str(), -1, nullptr);
    sqlite3_bind_int(stmt, 3, int(rule.type));
    sqlite3_bind_int(stmt, 4, rule.access_mask);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        logA("[ERROR] InsertRule failed: cant insert (%s)", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_finalize(stmt);

    logA("[DEBUG] InsertRule success");

    return true;
}
}  // namespace database
