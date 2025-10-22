#include "database.h"
#include "common/dacl/dacl.h"

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
                id          INTEGER PRIMARY KEY,
                path        TEXT,
                user        TEXT,
                sid         TEXT,
                type        INTEGER,
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
        R"(INSERT INTO rules (path, user, sid, type, access_mask) VALUES (?, ?, ?, ?, ?);)";

    sqlite3_stmt *stmt{};
    if (sqlite3_prepare_v2(db, q, -1, &stmt, nullptr)) {
        logA("[ERROR] InsertRule failed: can't prepare");
        return false;
    }

    sqlite3_bind_text(stmt, 1, rule.path.c_str(), -1, nullptr);
    sqlite3_bind_text(stmt, 2, rule.user.c_str(), -1, nullptr);
    sqlite3_bind_text(stmt, 3, rule.sid.c_str(), -1, nullptr);
    sqlite3_bind_int(stmt, 4, int(rule.type));
    sqlite3_bind_int(stmt, 5, rule.access_mask);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        logA("[ERROR] InsertRule failed: cant insert (%s)", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_finalize(stmt);

    logA("[DEBUG] InsertRule success");

    return true;
}

bool DeleteRule(const dacl::Rule &rule) {
    if (db == nullptr) {
        logA("[ERROR] Database not connected");
        return false;
    }

    constexpr const char *q = "DELETE FROM rules WHERE id = ?";

    sqlite3_stmt *stmt{};
    if (sqlite3_prepare_v2(db, q, -1, &stmt, nullptr)) {
        logA("[ERROR] DeleteRule failed: can't prepare");
        return false;
    }

    sqlite3_bind_int(stmt, 1, rule.id);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        logA("[ERROR] DeleteRule failed: cant delete (%s)", sqlite3_errmsg(db));
        return false;
    }

    sqlite3_finalize(stmt);

    logA("[DEBUG] DeleteRule success");

    return true;
}

std::vector<dacl::Rule> GetRules(const dacl::Rule &in) {
    std::vector<dacl::Rule> res;

    if (db == nullptr) {
        logA("[ERROR] Database not connected");
        return res;
    }

    std::string where = "1";
    std::vector<std::string> args{};

    if (!in.user.empty()) {
        where = std::format("{} AND {}", where, "user = ?");
        args.push_back(in.user);
    }

    if (!in.path.empty()) {
        where = std::format("{} AND {}", where, "path = ?");
        args.push_back(in.path);
    }

    std::string q = std::format(
        "SELECT id, path, user, sid, type, access_mask FROM rules WHERE {} "
        "ORDER BY "
        "id;",
        where);

    sqlite3_stmt *stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, q.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logA("[ERROR] GetRules prepare failed: %s", sqlite3_errmsg(db));
        return res;
    }

    {
        int i = 1;
        for (const auto &arg : args) {
            sqlite3_bind_text(stmt, i++, arg.c_str(), -1, nullptr);
        }
    }

    res.reserve(32);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        dacl::Rule r{};

        {
            int v = sqlite3_column_int(stmt, 0);
            r.id = v;
        }

        {
            const unsigned char *p = sqlite3_column_text(stmt, 1);
            int n = sqlite3_column_bytes(stmt, 1);
            r.path.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
        }

        {
            const unsigned char *p = sqlite3_column_text(stmt, 2);
            int n = sqlite3_column_bytes(stmt, 2);
            r.user.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
        }

        {
            const unsigned char *p = sqlite3_column_text(stmt, 3);
            int n = sqlite3_column_bytes(stmt, 3);
            r.sid.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
        }

        {
            int v = sqlite3_column_int(stmt, 4);
            r.type = dacl::Rule::Type(v);
        }

        r.access_mask = u8(sqlite3_column_int(stmt, 5));

        res.push_back(std::move(r));
    }

    if (rc != SQLITE_DONE) {
        logA("[ERROR] GetRules step failed: %s", sqlite3_errmsg(db));
    }
    logA("[DEBUG] GetRules selected %d rules", res.size());

    sqlite3_finalize(stmt);
    return res;
}

std::optional<dacl::Rule> GetRule(int id) {
    constexpr const char *q =
        "SELECT id, path, user, sid, type, access_mask FROM rules WHERE id = "
        "?;";
    sqlite3_stmt *stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, q, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        logA("[ERROR] GetRule prepare failed: %s", sqlite3_errmsg(db));
        return std::nullopt;
    }

    sqlite3_bind_int(stmt, 1, id);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        logA("[ERROR] GetRule step failed");
        return std::nullopt;
    }

    dacl::Rule r{};

    {
        int v = sqlite3_column_int(stmt, 0);
        r.id = v;
    }

    {
        const unsigned char *p = sqlite3_column_text(stmt, 1);
        int n = sqlite3_column_bytes(stmt, 1);
        r.path.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
    }

    {
        const unsigned char *p = sqlite3_column_text(stmt, 2);
        int n = sqlite3_column_bytes(stmt, 2);
        r.user.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
    }

    {
        const unsigned char *p = sqlite3_column_text(stmt, 3);
        int n = sqlite3_column_bytes(stmt, 3);
        r.sid.assign(p ? reinterpret_cast<const char *>(p) : "", usize(n));
    }

    {
        int v = sqlite3_column_int(stmt, 4);
        r.type = dacl::Rule::Type(v);
    }

    r.access_mask = u8(sqlite3_column_int(stmt, 5));

    return r;
}
}  // namespace database
