/*
 * log_analyzer.cpp
 * ═══════════════════════════════════════════════════════════════
 * High-performance multi-format log analyzer using memory-mapped I/O.
 *
 * Supported formats (auto-detected):
 *   - Nginx/Apache combined log
 *   - HDFS DataNode / NameSystem logs
 *   - Syslog (BSD-style)
 *   - JSON-per-line logs
 *
 * Features:
 *   - mmap with sliding window (handles files larger than RAM)
 *   - Zero-copy line parsing (no heap allocation per line)
 *   - Auto-detection by sampling first 8 KB
 *   - Extracts: status codes, top IPs, top endpoints, error rate,
 *               latency percentiles (p50/p95/p99), bytes transferred,
 *               requests per hour, method breakdown
 *   - Outputs: human-readable report + JSON for dashboard
 *
 * Compile:
 *   g++ -O2 -std=c++17 -o log_analyzer log_analyzer.cpp
 *
 * Usage:
 *   ./log_analyzer server.log [report.json]
 * ═══════════════════════════════════════════════════════════════
 */

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <numeric>
#include <cctype>

// POSIX mmap
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

// ─────────────────────────────────────────────────────────────
// Log type enum
// ─────────────────────────────────────────────────────────────

enum class LogType { UNKNOWN, NGINX, HDFS, SYSLOG, JSON_LOG, HPC, UNIVERSAL };

static const char* logTypeName(LogType t) {
    switch (t) {
        case LogType::NGINX:    return "NGINX";
        case LogType::HDFS:     return "HDFS";
        case LogType::SYSLOG:   return "SYSLOG";
        case LogType::JSON_LOG: return "JSON";
        case LogType::HPC:      return "HPC";
        case LogType::UNIVERSAL:return "UNIVERSAL";
        default:                return "UNKNOWN";
    }
}

// ─────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────

struct Stats {
    // Counters
    uint64_t totalRequests  = 0;
    uint64_t totalBytes     = 0;
    uint64_t errorRequests  = 0;   // 4xx + 5xx  (or WARN+ERROR+FATAL for HDFS)
    uint64_t clientErrors   = 0;   // 4xx        (or WARN+ERROR for HDFS)
    uint64_t serverErrors   = 0;   // 5xx        (or FATAL for HDFS)

    // Distributions
    std::unordered_map<std::string, uint64_t> statusCount;
    std::unordered_map<std::string, uint64_t> ipCount;
    std::unordered_map<std::string, uint64_t> endpointCount;
    std::unordered_map<std::string, uint64_t> methodCount;
    std::unordered_map<int, uint64_t>         hourCount;    // 0-23

    // Latency samples (ms) — capped at 2M for memory
    std::vector<uint32_t> latencies;

    // Parse errors
    uint64_t parseErrors = 0;

    // Sub-type for universal/generic logs
    std::string subType;
};

// ─────────────────────────────────────────────────────────────
// Fast string_view-like helpers (no allocation)
// ─────────────────────────────────────────────────────────────

struct Sv { const char* ptr; size_t len; };

static inline bool sv_eq(Sv a, const char* b) {
    size_t bl = strlen(b);
    return a.len == bl && memcmp(a.ptr, b, bl) == 0;
}

static inline std::string sv_str(Sv s) { return std::string(s.ptr, s.len); }

static inline int sv_int(Sv s) {
    int v = 0;
    for (size_t i = 0; i < s.len; ++i) {
        if (s.ptr[i] < '0' || s.ptr[i] > '9') break;
        v = v * 10 + (s.ptr[i] - '0');
    }
    return v;
}

static inline int64_t sv_int64(Sv s) {
    int64_t v = 0;
    for (size_t i = 0; i < s.len; ++i) {
        if (s.ptr[i] < '0' || s.ptr[i] > '9') break;
        v = v * 10 + (s.ptr[i] - '0');
    }
    return v;
}

// Case-insensitive substring search in a buffer
static const char* memmem_ci(const char* hay, size_t hlen, const char* needle, size_t nlen) {
    if (nlen > hlen) return nullptr;
    for (size_t i = 0; i <= hlen - nlen; ++i) {
        bool match = true;
        for (size_t j = 0; j < nlen; ++j) {
            if (tolower((unsigned char)hay[i+j]) != tolower((unsigned char)needle[j])) {
                match = false; break;
            }
        }
        if (match) return hay + i;
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────
// Line parser function pointer type
// ─────────────────────────────────────────────────────────────

typedef bool (*LineParser)(const char*, size_t, Stats&);

// ─────────────────────────────────────────────────────────────
// Parser 1: Nginx combined log format
//   IP - - [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/x.x" STATUS BYTES LATENCY_MS "ref" "ua"
// ─────────────────────────────────────────────────────────────

static bool parseNginxLine(const char* line, size_t len, Stats& s) {
    const char* p   = line;
    const char* end = line + len;

#define SKIP(c)  while (p < end && *p != (c)) ++p; if (p >= end) return false; ++p;
#define PEEK(c)  (p < end && *p == (c))
#define FIELD_TO(c, sv) { sv.ptr = p; while (p < end && *p != (c)) ++p; sv.len = p - sv.ptr; if (p >= end) return false; ++p; }

    // 1. IP address
    Sv ip; FIELD_TO(' ', ip);

    // 2. skip "- - ["
    SKIP(' '); SKIP('[');

    // 3. Timestamp: DD/Mon/YYYY:HH:MM:SS +0000
    SKIP('/'); SKIP('/'); SKIP(':');  // skip day/mon/year
    Sv hour_sv; FIELD_TO(':', hour_sv);
    int hour = sv_int(hour_sv);
    SKIP(']'); SKIP(' '); SKIP('"');

    // 4. HTTP method
    Sv method; FIELD_TO(' ', method);

    // 5. Path (endpoint)
    Sv path; FIELD_TO(' ', path);
    Sv endpoint = path;
    for (size_t i = 0; i < path.len; ++i) {
        if (path.ptr[i] == '?') { endpoint.len = i; break; }
    }

    // 6. Skip HTTP version and closing quote
    SKIP('"'); SKIP(' ');

    // 7. Status code
    Sv status; FIELD_TO(' ', status);

    // 8. Bytes
    Sv bytes_sv; FIELD_TO(' ', bytes_sv);
    uint64_t bytes = (uint64_t)sv_int(bytes_sv);

    // 9. Latency (ms) — custom field after bytes
    Sv lat_sv; FIELD_TO(' ', lat_sv);
    uint32_t latency = (uint32_t)sv_int(lat_sv);

#undef SKIP
#undef PEEK
#undef FIELD_TO

    // ── Aggregate ────────────────────────────────────────────
    ++s.totalRequests;
    s.totalBytes += bytes;

    std::string st = sv_str(status);
    ++s.statusCount[st];
    if (!st.empty()) {
        char c = st[0];
        if (c == '4') { ++s.errorRequests; ++s.clientErrors; }
        else if (c == '5') { ++s.errorRequests; ++s.serverErrors; }
    }

    ++s.ipCount[sv_str(ip)];

    std::string ep = sv_str(endpoint);
    if (ep.size() > 40) ep = ep.substr(0, 40) + "…";
    ++s.endpointCount[ep];

    ++s.methodCount[sv_str(method)];

    if (hour >= 0 && hour <= 23) ++s.hourCount[hour];

    if (latency > 0 && s.latencies.size() < 2000000) {
        s.latencies.push_back(latency);
    }

    return true;
}

// ─────────────────────────────────────────────────────────────
// Parser 2: HDFS log
//   YYMMDD HHMMSS threadID LEVEL component: message
// ─────────────────────────────────────────────────────────────

static bool parseHDFSLine(const char* line, size_t len, Stats& s) {
    const char* p   = line;
    const char* end = line + len;

    // Need at least: "YYMMDD HHMMSS TID LEVEL comp: msg"
    // 1. Date field (6 digits)
    if (len < 20) return false;
    // Verify date field has digits
    for (int i = 0; i < 6; ++i) {
        if (p[i] < '0' || p[i] > '9') return false;
    }
    p += 6;
    if (p >= end || *p != ' ') return false;
    ++p;

    // 2. Time field HHMMSS (6 digits) — extract hour
    const char* timeStart = p;
    for (int i = 0; i < 6; ++i) {
        if (p >= end || p[i] < '0' || p[i] > '9') return false;
    }
    int hour = (timeStart[0] - '0') * 10 + (timeStart[1] - '0');
    p += 6;
    if (p >= end || *p != ' ') return false;
    ++p;

    // 3. Thread ID (digits)
    const char* tidStart = p;
    while (p < end && *p >= '0' && *p <= '9') ++p;
    if (p == tidStart || p >= end || *p != ' ') return false;
    ++p;

    // 4. Log level
    const char* levelStart = p;
    while (p < end && *p != ' ') ++p;
    size_t levelLen = p - levelStart;
    if (p >= end) return false;
    ++p;

    std::string level(levelStart, levelLen);

    // 5. Component (up to ':')
    const char* compStart = p;
    while (p < end && *p != ':') ++p;
    size_t compLen = p - compStart;
    if (p >= end) return false;
    std::string component(compStart, compLen);
    ++p; // skip ':'
    // skip space after colon
    if (p < end && *p == ' ') ++p;

    // 6. Message — rest of line
    const char* msgStart = p;
    size_t msgLen = end - p;

    // ── Aggregate ────────────────────────────────────────────
    ++s.totalRequests;

    // Map level to statusCount
    ++s.statusCount[level];

    // Error classification
    if (level == "WARN" || level == "ERROR") {
        ++s.errorRequests;
        ++s.clientErrors;
    } else if (level == "FATAL") {
        ++s.errorRequests;
        ++s.serverErrors;
    }

    // Component → endpointCount
    if (component.size() > 40) component = component.substr(0, 40) + "…";
    ++s.endpointCount[component];

    // First word of message → methodCount
    if (msgLen > 0) {
        const char* wend_ptr = msgStart;
        while (wend_ptr < end && *wend_ptr != ' ' && *wend_ptr != '\t') ++wend_ptr;
        std::string firstWord(msgStart, wend_ptr - msgStart);
        if (!firstWord.empty()) {
            ++s.methodCount[firstWord];
        }
    }

    // Extract IPs from message: "src: /IP:port", "from /IP", "dest: /IP:port", "to /IP:port"
    {
        const char* scan = msgStart;
        const char* msgEnd = end;
        while (scan < msgEnd) {
            const char* slash = static_cast<const char*>(memchr(scan, '/', msgEnd - scan));
            if (!slash) break;
            // Check if next chars form an IP: digits and dots
            const char* ipStart = slash + 1;
            const char* ipEnd = ipStart;
            int dots = 0;
            while (ipEnd < msgEnd && ((*ipEnd >= '0' && *ipEnd <= '9') || *ipEnd == '.')) {
                if (*ipEnd == '.') ++dots;
                ++ipEnd;
            }
            if (dots == 3 && (ipEnd - ipStart) >= 7) {
                std::string ip(ipStart, ipEnd - ipStart);
                ++s.ipCount[ip];
            }
            scan = (ipEnd > slash + 1) ? ipEnd : slash + 1;
        }
    }

    // Extract block size from "of size NNNN"
    {
        const char* sizeStr = "of size ";
        size_t sizeStrLen = 8;
        const char* found = static_cast<const char*>(
            memmem(msgStart, msgLen, sizeStr, sizeStrLen));
        if (found) {
            const char* numStart = found + sizeStrLen;
            int64_t sz = 0;
            while (numStart < end && *numStart >= '0' && *numStart <= '9') {
                sz = sz * 10 + (*numStart - '0');
                ++numStart;
            }
            s.totalBytes += sz;
        }
    }

    // Hour
    if (hour >= 0 && hour <= 23) ++s.hourCount[hour];

    return true;
}

// ─────────────────────────────────────────────────────────────
// Parser 3: Syslog (BSD)
//   Mon DD HH:MM:SS hostname program[PID]: message
// ─────────────────────────────────────────────────────────────

static bool parseSyslogLine(const char* line, size_t len, Stats& s) {
    const char* p   = line;
    const char* end = line + len;

    // Minimum length check
    if (len < 16) return false;

    // 1. Month (3 chars)
    static const char* months[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    bool validMonth = false;
    for (auto m : months) {
        if (len >= 3 && memcmp(p, m, 3) == 0) { validMonth = true; break; }
    }
    if (!validMonth) return false;
    p += 3;
    if (p >= end || *p != ' ') return false;
    ++p;

    // 2. Day (1-2 digits, possibly space-padded)
    while (p < end && *p == ' ') ++p;
    while (p < end && *p >= '0' && *p <= '9') ++p;
    if (p >= end || *p != ' ') return false;
    ++p;

    // 3. Time HH:MM:SS — extract hour
    if (p + 8 > end) return false;
    if (p[2] != ':' || p[5] != ':') return false;
    int hour = (p[0] - '0') * 10 + (p[1] - '0');
    p += 8;
    if (p >= end || *p != ' ') return false;
    ++p;

    // 4. Hostname
    const char* hostStart = p;
    while (p < end && *p != ' ') ++p;
    size_t hostLen = p - hostStart;
    if (p >= end) return false;
    std::string hostname(hostStart, hostLen);
    ++p;

    // 5. Program[PID]: or Program:
    const char* progStart = p;
    while (p < end && *p != '[' && *p != ':') ++p;
    size_t progLen = p - progStart;
    if (p >= end) return false;
    std::string program(progStart, progLen);

    // Skip [PID] if present
    if (*p == '[') {
        while (p < end && *p != ']') ++p;
        if (p < end) ++p; // skip ']'
    }
    // Skip ':'
    if (p < end && *p == ':') ++p;
    // Skip space
    if (p < end && *p == ' ') ++p;

    // 6. Message — rest of line
    const char* msgStart = p;
    size_t msgLen = end - p;

    // ── Aggregate ────────────────────────────────────────────
    ++s.totalRequests;

    // Hostname → ipCount
    ++s.ipCount[hostname];

    // Program → endpointCount
    ++s.endpointCount[program];

    // Detect errors via keywords
    bool isError = false;
    if (msgLen > 0) {
        if (memmem_ci(msgStart, msgLen, "error", 5) ||
            memmem_ci(msgStart, msgLen, "fail", 4) ||
            memmem_ci(msgStart, msgLen, "denied", 6)) {
            isError = true;
        }
    }

    if (isError) {
        ++s.errorRequests;
        ++s.clientErrors;
        ++s.statusCount["ERROR"];
    } else {
        ++s.statusCount["OK"];
    }

    // First word of message → methodCount
    if (msgLen > 0) {
        const char* wend_ptr = msgStart;
        while (wend_ptr < end && *wend_ptr != ' ' && *wend_ptr != '\t') ++wend_ptr;
        std::string firstWord(msgStart, wend_ptr - msgStart);
        if (!firstWord.empty()) {
            ++s.methodCount[firstWord];
        }
    }

    // Hour
    if (hour >= 0 && hour <= 23) ++s.hourCount[hour];

    return true;
}

// ─────────────────────────────────────────────────────────────
// Parser 4: JSON-per-line
//   { "key": "value", ... }
// ─────────────────────────────────────────────────────────────

// Helper: extract a JSON string value for a given key
static bool jsonExtractString(const char* line, size_t len,
                              const char* key, std::string& out) {
    // Search for "key":"value" or "key": "value"
    size_t klen = strlen(key);
    // Build search pattern: "key"
    char pattern[256];
    int plen = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (plen <= 0 || (size_t)plen >= sizeof(pattern)) return false;

    const char* found = static_cast<const char*>(
        memmem(line, len, pattern, plen));
    if (!found) return false;

    const char* p = found + plen;
    const char* end = line + len;

    // Skip whitespace and colon
    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) ++p;
    if (p >= end) return false;

    if (*p == '"') {
        ++p;
        const char* vstart = p;
        while (p < end && *p != '"') {
            if (*p == '\\' && p + 1 < end) { p += 2; continue; }
            ++p;
        }
        out.assign(vstart, p - vstart);
        return true;
    }
    return false;
}

// Helper: extract a JSON numeric value for a given key
static bool jsonExtractInt(const char* line, size_t len,
                           const char* key, int64_t& out) {
    size_t klen = strlen(key);
    char pattern[256];
    int plen = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    if (plen <= 0 || (size_t)plen >= sizeof(pattern)) return false;

    const char* found = static_cast<const char*>(
        memmem(line, len, pattern, plen));
    if (!found) return false;

    const char* p = found + plen;
    const char* end = line + len;

    while (p < end && (*p == ' ' || *p == '\t' || *p == ':')) ++p;
    if (p >= end) return false;

    // Could be a quoted number or raw number
    if (*p == '"') {
        ++p;
        // Parse number inside quotes
    }

    bool neg = false;
    if (p < end && *p == '-') { neg = true; ++p; }
    if (p >= end || *p < '0' || *p > '9') return false;
    int64_t v = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        v = v * 10 + (*p - '0');
        ++p;
    }
    out = neg ? -v : v;
    return true;
}

static bool parseJsonLine(const char* line, size_t len, Stats& s) {
    if (len < 2) return false;

    // Skip leading whitespace
    const char* p = line;
    const char* end = line + len;
    while (p < end && (*p == ' ' || *p == '\t')) ++p;
    if (p >= end || *p != '{') return false;

    ++s.totalRequests;

    // Try to extract IP
    std::string val;
    if (jsonExtractString(p, end - p, "ip", val) ||
        jsonExtractString(p, end - p, "remote_addr", val) ||
        jsonExtractString(p, end - p, "client_ip", val)) {
        if (!val.empty()) ++s.ipCount[val];
    }

    // Try to extract endpoint/path
    val.clear();
    if (jsonExtractString(p, end - p, "path", val) ||
        jsonExtractString(p, end - p, "endpoint", val) ||
        jsonExtractString(p, end - p, "url", val)) {
        if (!val.empty()) {
            if (val.size() > 40) val = val.substr(0, 40) + "…";
            ++s.endpointCount[val];
        }
    }

    // Try to extract status
    val.clear();
    int64_t numval = 0;
    if (jsonExtractString(p, end - p, "level", val) ||
        jsonExtractString(p, end - p, "status", val)) {
        if (!val.empty()) {
            ++s.statusCount[val];
            // Check for error status
            if (!val.empty() && val[0] == '4') { ++s.errorRequests; ++s.clientErrors; }
            else if (!val.empty() && val[0] == '5') { ++s.errorRequests; ++s.serverErrors; }
            // Check for error/warn level strings
            if (val == "error" || val == "ERROR") { ++s.errorRequests; ++s.clientErrors; }
            else if (val == "fatal" || val == "FATAL") { ++s.errorRequests; ++s.serverErrors; }
        }
    } else if (jsonExtractInt(p, end - p, "status", numval)) {
        std::string st = std::to_string(numval);
        ++s.statusCount[st];
        if (numval >= 400 && numval < 500) { ++s.errorRequests; ++s.clientErrors; }
        else if (numval >= 500) { ++s.errorRequests; ++s.serverErrors; }
    }

    // Try to extract method
    val.clear();
    if (jsonExtractString(p, end - p, "method", val)) {
        if (!val.empty()) ++s.methodCount[val];
    }

    // Try to extract bytes
    numval = 0;
    if (jsonExtractInt(p, end - p, "bytes", numval) ||
        jsonExtractInt(p, end - p, "body_bytes_sent", numval)) {
        s.totalBytes += numval;
    }

    // Try to extract latency
    numval = 0;
    if (jsonExtractInt(p, end - p, "latency", numval) ||
        jsonExtractInt(p, end - p, "duration", numval) ||
        jsonExtractInt(p, end - p, "response_time", numval)) {
        if (numval > 0 && s.latencies.size() < 2000000) {
            s.latencies.push_back((uint32_t)numval);
        }
    }

    // Try to extract timestamp for hour
    val.clear();
    if (jsonExtractString(p, end - p, "timestamp", val) ||
        jsonExtractString(p, end - p, "time", val) ||
        jsonExtractString(p, end - p, "@timestamp", val)) {
        // Look for HH: pattern in timestamp
        for (size_t i = 0; i + 2 < val.size(); ++i) {
            if (val[i] == 'T' || val[i] == ' ') {
                if (i + 3 < val.size() && val[i+1] >= '0' && val[i+1] <= '2' &&
                    val[i+2] >= '0' && val[i+2] <= '9' && val[i+3] == ':') {
                    int hr = (val[i+1] - '0') * 10 + (val[i+2] - '0');
                    if (hr >= 0 && hr <= 23) ++s.hourCount[hr];
                    break;
                }
            }
        }
    }

    return true;
}

// ─────────────────────────────────────────────────────────────
// Parser 5: HPC cluster log format
//   Supports two common HPC/BGL log layouts:
//
//   Format A (6-token, Blue Gene/L standard — most common):
//     <SeqID> <NodeID> <Facility> <EventType> <EpochTimestamp> <SeverityCode> <Message>
//     Example: 345940 node-231 unix.hw state_change.unavailable 1084369936 1 Component State Change...
//
//   Format B (7-token, with explicit subsystem field):
//     <SeqID> <Component> <NodeID> <Facility> <Subsystem> <EpochTimestamp> <SeverityCode> <Message>
//     Example: 460903 resourcemgmtdaeomon node-25 server subsys 1145552216 1 failed to configure...
//
//   The parser auto-detects which layout a line uses by checking
//   where the Unix timestamp (9-10 digit number) appears.
// ─────────────────────────────────────────────────────────────

// Helper: check if an Sv is a valid 9-10 digit Unix timestamp
static bool isUnixTimestamp(const Sv& tok) {
    if (tok.len < 9 || tok.len > 10) return false;
    for (size_t i = 0; i < tok.len; ++i) {
        if (tok.ptr[i] < '0' || tok.ptr[i] > '9') return false;
    }
    return true;
}

static bool parseHPCLine(const char* line, size_t len, Stats& s) {
    const char* p = line;
    const char* end = line + len;

    // Helper to extract a whitespace-separated token (spaces or tabs)
    // Uses a separate pointer so we can save/restore parse position
    struct TokenReader {
        const char* p;
        const char* end;
        bool get(Sv& tok) {
            while (p < end && (*p == ' ' || *p == '\t')) ++p;
            if (p >= end) return false;
            tok.ptr = p;
            while (p < end && *p != ' ' && *p != '\t') ++p;
            tok.len = p - tok.ptr;
            return tok.len > 0;
        }
    };

    // Read up to 8 tokens to probe the line structure
    Sv tokens[8];
    int ntokens = 0;
    {
        TokenReader reader{p, end};
        while (ntokens < 8 && reader.get(tokens[ntokens])) {
            ++ntokens;
        }
        p = reader.p;  // advance past consumed tokens
    }

    // We need at least 5 tokens for the shortest format (4 header + timestamp)
    if (ntokens < 5) return false;

    // Validate first token is a sequence ID (all digits)
    for (size_t i = 0; i < tokens[0].len; ++i) {
        if (tokens[0].ptr[i] < '0' || tokens[0].ptr[i] > '9') return false;
    }

    // Determine format by probing where the Unix timestamp is
    // Format C: timestamp at tokens[3] (4-token header, no node field)
    // Format A: timestamp at tokens[4] (6-token header)
    // Format B: timestamp at tokens[5] (7-token header)
    Sv time_sv, sev_sv;
    Sv node_sv, component_sv, facility_sv, subsystem_sv;
    const char* msg_p;  // where the message starts
    bool hasSubsystem = false;

    if (ntokens >= 5 && isUnixTimestamp(tokens[3])) {
        // Format C: seq facility event_type timestamp severity [message...]
        //           [0]  [1]      [2]        [3]      [4]     [5...]
        node_sv      = tokens[1]; // use facility as node placeholder
        facility_sv  = tokens[1];
        component_sv = tokens[2];
        subsystem_sv = tokens[1];
        time_sv      = tokens[3];
        sev_sv       = tokens[4];
        hasSubsystem = false;

        const char* scan = tokens[4].ptr + tokens[4].len;
        while (scan < end && (*scan == ' ' || *scan == '\t')) ++scan;
        msg_p = scan;

    } else if (isUnixTimestamp(tokens[4]) && ntokens >= 6) {
        // Format A: seq node facility event_type timestamp severity [message...]
        //           [0]  [1]   [2]      [3]       [4]      [5]     [6...]
        node_sv      = tokens[1];
        facility_sv  = tokens[2];
        component_sv = tokens[3]; // event_type goes to component
        subsystem_sv = tokens[2]; // use facility as subsystem fallback
        time_sv      = tokens[4];
        sev_sv       = tokens[5];
        hasSubsystem = false;

        // Message starts after the 6th token
        // Re-scan from the start to find where token[6] begins
        const char* scan = tokens[5].ptr + tokens[5].len;
        while (scan < end && (*scan == ' ' || *scan == '\t')) ++scan;
        msg_p = scan;

    } else if (ntokens >= 7 && isUnixTimestamp(tokens[5])) {
        // Format B: seq comp node facility subsys timestamp severity [message...]
        //           [0]  [1]  [2]   [3]     [4]    [5]      [6]     [7...]
        component_sv = tokens[1];
        node_sv      = tokens[2];
        facility_sv  = tokens[3];
        subsystem_sv = tokens[4];
        time_sv      = tokens[5];
        sev_sv       = tokens[6];
        hasSubsystem = true;

        // Message starts after the 7th token
        const char* scan = tokens[6].ptr + tokens[6].len;
        while (scan < end && (*scan == ' ' || *scan == '\t')) ++scan;
        msg_p = scan;

    } else {
        return false; // Neither format matched
    }

    // Parse timestamp
    int64_t ts = sv_int64(time_sv);
    time_t t_val = (time_t)ts;
    struct tm* tm_info = gmtime(&t_val);
    int hour = tm_info ? tm_info->tm_hour : -1;

    // Message
    size_t msg_len = (msg_p < end) ? (size_t)(end - msg_p) : 0;
    const char* msg_start = msg_p;

    // Severity: try numeric first, then keyword
    bool sevIsNumeric = true;
    for (size_t i = 0; i < sev_sv.len; ++i) {
        if (sev_sv.ptr[i] < '0' || sev_sv.ptr[i] > '9') {
            // Allow leading '-' for negative codes like -1
            if (i == 0 && sev_sv.ptr[i] == '-') continue;
            sevIsNumeric = false;
            break;
        }
    }

    int sev = sevIsNumeric ? sv_int(sev_sv) : -99;

    // ── Aggregate ────────────────────────────────────────────
    ++s.totalRequests;

    // ── Severity classification ──────────────────────────────
    // In Blue Gene/L and many HPC logs, the numeric severity code
    // (typically 0, 1, or -1) does NOT correspond to syslog-style
    // levels. Code "1" simply means "event logged" and covers
    // everything from normal operations to critical failures.
    //
    // The real severity is determined from MESSAGE CONTENT:
    //   - "normal", "running", "success", "configured" → INFO
    //   - "warning"                                    → WARN
    //   - "error", "fail", "critical", "fatal"         → ERROR
    //   - "not responding", "unavailable"              → ERROR

    std::string level = "INFO";
    bool isError = false;
    bool isWarning = false;

    // For non-numeric severity tokens, check the token itself first
    if (!sevIsNumeric) {
        std::string sevStr = sv_str(sev_sv);
        if (sevStr == "FATAL" || sevStr == "CRIT" || sevStr == "CRITICAL" ||
            sevStr == "EMERGENCY" || sevStr == "EMERG") {
            level = "ERROR"; isError = true;
        } else if (sevStr == "ERR" || sevStr == "ERROR") {
            level = "ERROR"; isError = true;
        } else if (sevStr == "WARN" || sevStr == "WARNING") {
            level = "WARN"; isWarning = true;
        } else if (sevStr == "NOTICE") {
            level = "NOTICE";
        } else if (sevStr == "INFO" || sevStr == "NORMAL") {
            level = "INFO";
        } else if (sevStr == "DEBUG" || sevStr == "TRACE") {
            level = "DEBUG";
        } else {
            level = sevStr;
        }
    }

    // Primary severity classification: scan MESSAGE CONTENT for keywords.
    // This takes priority over the numeric severity code for HPC/BGL logs.
    if (msg_len > 0) {
        // Check for error/critical keywords first (highest priority)
        if (!isError) {
            if (memmem_ci(msg_start, msg_len, "fatal", 5) ||
                memmem_ci(msg_start, msg_len, "critical", 8) ||
                memmem_ci(msg_start, msg_len, "not responding", 14) ||
                memmem_ci(msg_start, msg_len, "unavailable", 11) ||
                memmem_ci(msg_start, msg_len, "denied", 6)) {
                level = "ERROR";
                isError = true;
            }
        }

        // Check for error/fail keywords — but exclude common false positives
        // like "Linkerror event interval expired" which is informational
        if (!isError) {
            bool hasError = memmem_ci(msg_start, msg_len, "error", 5) != nullptr;
            bool hasFail  = memmem_ci(msg_start, msg_len, "fail", 4)  != nullptr;

            if (hasError || hasFail) {
                // Exclude known informational patterns that contain "error"
                bool isInfoPattern = false;
                if (hasError) {
                    // "Linkerror event interval expired" is a periodic status message
                    if (memmem_ci(msg_start, msg_len, "interval expired", 16) ||
                        memmem_ci(msg_start, msg_len, "errors remain", 13)) {
                        isInfoPattern = true;
                    }
                }
                if (!isInfoPattern) {
                    level = "ERROR";
                    isError = true;
                }
            }
        }

        // Check for warning keywords
        if (!isError && !isWarning) {
            if (memmem_ci(msg_start, msg_len, "warning", 7)) {
                level = "WARN";
                isWarning = true;
            }
        }

        // Check for normal/informational keywords — override numeric code
        if (!isError && !isWarning) {
            if (memmem_ci(msg_start, msg_len, "normal", 6) ||
                memmem_ci(msg_start, msg_len, "success", 7) ||
                memmem_ci(msg_start, msg_len, "running", 7) ||
                memmem_ci(msg_start, msg_len, "configured", 10) ||
                memmem_ci(msg_start, msg_len, "active", 6)) {
                level = "INFO";
            }
        }
    }

    // Fallback: if no message keywords matched and we have a numeric code,
    // use a conservative mapping (most BGL events with code 1 are informational)
    // Only codes explicitly indicating severity are 0=INFO, -1=UNDETERMINED

    ++s.statusCount[level];
    if (isError) {
        ++s.errorRequests;
        ++s.clientErrors;
    } else if (isWarning) {
        ++s.errorRequests;
        ++s.clientErrors;
    }

    // Node ID -> ipCount
    ++s.ipCount[sv_str(node_sv)];

    // Component/EventType -> endpointCount
    std::string comp_str = sv_str(component_sv);
    if (comp_str.size() > 40) comp_str = comp_str.substr(0, 40) + "…";
    ++s.endpointCount[comp_str];

    // Facility or Subsystem -> methodCount
    std::string method = hasSubsystem ? sv_str(subsystem_sv) : sv_str(facility_sv);
    if (!method.empty()) {
        ++s.methodCount[method];
    }

    // Hour
    if (hour >= 0 && hour <= 23) {
        ++s.hourCount[hour];
    }

    return true;
}

static bool parseUniversalLine(const char* line, size_t len, Stats& s) {
    if (len == 0) return false;

    // ── Log Level ──
    std::string level = "INFO";
    bool levelFound = false;

    const char* fatalWords[] = { "FATAL", "CRITICAL", "SEVERE", "EMERGENCY" };
    const char* errorWords[] = { "ERROR", "FAIL", "FAILURE", "DENIED", "EXCEPTION", "ERR" };
    const char* warnWords[]  = { "WARN", "WARNING" };
    const char* debugWords[] = { "DEBUG", "TRACE" };
    const char* infoWords[]  = { "INFO", "NOTICE", "SUCCESS", "OK" };

    bool isError = false;
    bool isFatal = false;
    bool isWarning = false;
    bool isDebug = false;

    for (auto w : fatalWords) {
        if (memmem_ci(line, len, w, strlen(w))) {
            level = w; isFatal = true; levelFound = true; break;
        }
    }
    if (!levelFound) {
        for (auto w : errorWords) {
            if (memmem_ci(line, len, w, strlen(w))) {
                level = w; isError = true; levelFound = true; break;
            }
        }
    }
    if (!levelFound) {
        for (auto w : warnWords) {
            if (memmem_ci(line, len, w, strlen(w))) {
                level = w; isWarning = true; levelFound = true; break;
            }
        }
    }
    if (!levelFound) {
        for (auto w : debugWords) {
            if (memmem_ci(line, len, w, strlen(w))) {
                level = w; isDebug = true; levelFound = true; break;
            }
        }
    }
    if (!levelFound) {
        for (auto w : infoWords) {
            if (memmem_ci(line, len, w, strlen(w))) {
                level = w; levelFound = true; break;
            }
        }
    }

    ++s.totalRequests;
    ++s.statusCount[level];
    if (isError) {
        ++s.errorRequests;
        ++s.clientErrors;
    } else if (isFatal) {
        ++s.errorRequests;
        ++s.serverErrors;
    } else if (isWarning) {
        ++s.errorRequests;
        ++s.clientErrors;
    }

    // ── Hour / Time ──
    int hour = -1;
    for (size_t i = 0; i + 4 < len; ++i) {
        if (line[i] >= '0' && line[i] <= '9' &&
            line[i+1] >= '0' && line[i+1] <= '9' &&
            line[i+2] == ':' &&
            line[i+3] >= '0' && line[i+3] <= '9' &&
            line[i+4] >= '0' && line[i+4] <= '9') {
            hour = (line[i] - '0') * 10 + (line[i+1] - '0');
            break;
        }
    }
    if (hour == -1) {
        // Look for a 10-digit Unix timestamp (seconds since epoch)
        for (size_t i = 0; i + 9 < len; ++i) {
            if (line[i] >= '1' && line[i] <= '2') { // Unix timestamp starts with 1 or 2
                bool allDigits = true;
                for (size_t j = 0; j < 10; ++j) {
                    if (line[i+j] < '0' || line[i+j] > '9') {
                        allDigits = false;
                        break;
                    }
                }
                if (allDigits) {
                    bool leftBound = (i == 0 || !isdigit((unsigned char)line[i-1]));
                    bool rightBound = (i + 10 == len || !isdigit((unsigned char)line[i+10]));
                    if (leftBound && rightBound) {
                        int64_t ts = 0;
                        for (size_t j = 0; j < 10; ++j) {
                            ts = ts * 10 + (line[i+j] - '0');
                        }
                        time_t t_val = (time_t)ts;
                        struct tm* tm_info = gmtime(&t_val);
                        if (tm_info) {
                            hour = tm_info->tm_hour;
                            break;
                        }
                    }
                }
            }
        }
    }
    if (hour >= 0 && hour <= 23) {
        ++s.hourCount[hour];
    }

    // ── IP Address ──
    for (size_t i = 0; i + 6 < len; ++i) {
        if (line[i] >= '0' && line[i] <= '9') {
            size_t start = i;
            int dots = 0;
            while (i < len && ((line[i] >= '0' && line[i] <= '9') || line[i] == '.')) {
                if (line[i] == '.') ++dots;
                ++i;
            }
            size_t ipLen = i - start;
            if (dots == 3 && ipLen >= 7 && ipLen <= 15) {
                std::string ip(line + start, ipLen);
                ++s.ipCount[ip];
                break;
            }
        }
    }

    // ── Endpoint / Path ──
    for (size_t i = 0; i < len; ++i) {
        if (line[i] == '/' && (i == 0 || (line[i-1] != '/' && line[i-1] != ':'))) {
            size_t start = i;
            while (i < len && (isalnum((unsigned char)line[i]) || line[i] == '/' || line[i] == '-' || line[i] == '_' || line[i] == '.' || line[i] == '?' || line[i] == '=' || line[i] == '&' || line[i] == '%')) {
                ++i;
            }
            size_t pathLen = i - start;
            if (pathLen > 1) {
                std::string ep(line + start, pathLen);
                size_t q = ep.find('?');
                if (q != std::string::npos) ep = ep.substr(0, q);
                if (ep.size() > 40) ep = ep.substr(0, 40) + "…";
                ++s.endpointCount[ep];
                break;
            }
        }
    }

    // ── Action / Method ──
    const char* actions[] = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
        "LOGIN", "LOGOUT", "AUTH", "CONNECT", "SEND", "RECEIVE",
        "START", "STOP", "RUN", "EXECUTE", "UP", "DOWN", "UPDATE",
        "CREATE", "SELECT", "INSERT", "COMMIT", "ROLLBACK"
    };
    bool actionFound = false;
    for (auto act : actions) {
        const char* found = static_cast<const char*>(memmem(line, len, act, strlen(act)));
        if (found) {
            bool leftOk = (found == line || !isalnum((unsigned char)*(found - 1)));
            bool rightOk = (found + strlen(act) == line + len || !isalnum((unsigned char)*(found + strlen(act))));
            if (leftOk && rightOk) {
                ++s.methodCount[act];
                actionFound = true;
                break;
            }
        }
    }
    if (!actionFound) {
        ++s.methodCount["ACTION"];
    }

    // ── Bytes ──
    const char* byteKeys[] = { "bytes=", "size=", "len=", "length=", "sent=" };
    bool bytesFound = false;
    for (auto k : byteKeys) {
        const char* found = static_cast<const char*>(memmem(line, len, k, strlen(k)));
        if (found) {
            const char* numStart = found + strlen(k);
            int64_t bytes = 0;
            while (numStart < line + len && *numStart >= '0' && *numStart <= '9') {
                bytes = bytes * 10 + (*numStart - '0');
                ++numStart;
            }
            if (bytes > 0) {
                s.totalBytes += bytes;
                bytesFound = true;
                break;
            }
        }
    }

    // ── Latency / Duration ──
    const char* latKeys[] = { "latency=", "duration=", "time=", "rt=", "resp=" };
    bool latFound = false;
    for (auto k : latKeys) {
        const char* found = static_cast<const char*>(memmem(line, len, k, strlen(k)));
        if (found) {
            const char* numStart = found + strlen(k);
            double val = 0;
            bool isFloat = false;
            double div = 10;
            while (numStart < line + len && ((*numStart >= '0' && *numStart <= '9') || *numStart == '.')) {
                if (*numStart == '.') {
                    isFloat = true;
                } else {
                    if (!isFloat) {
                        val = val * 10 + (*numStart - '0');
                    } else {
                        val = val + (double)(*numStart - '0') / div;
                        div *= 10;
                    }
                }
                ++numStart;
            }
            double mult = 1.0;
            if (numStart < line + len) {
                if (numStart + 1 < line + len && numStart[0] == 'm' && numStart[1] == 's') {
                    mult = 1.0;
                } else if (numStart[0] == 's') {
                    mult = 1000.0;
                }
            }
            uint32_t ms = (uint32_t)(val * mult);
            if (ms > 0 && s.latencies.size() < 2000000) {
                s.latencies.push_back(ms);
                latFound = true;
                break;
            }
        }
    }
    if (!latFound) {
        const char* msSuffix = "ms";
        const char* found = static_cast<const char*>(memmem(line, len, msSuffix, 2));
        if (found && found > line) {
            const char* p = found - 1;
            while (p >= line && *p == ' ') --p;
            if (p >= line && *p >= '0' && *p <= '9') {
                const char* numEnd = p + 1;
                while (p >= line && *p >= '0' && *p <= '9') --p;
                const char* numStart = p + 1;
                int64_t val = 0;
                for (const char* ptr = numStart; ptr < numEnd; ++ptr) {
                    val = val * 10 + (*ptr - '0');
                }
                if (val > 0 && s.latencies.size() < 2000000) {
                    s.latencies.push_back((uint32_t)val);
                }
            }
        }
    }

    return true;
}

static std::string detectSubLogType(const std::string& path, const char* buf, size_t len) {
    // 1. Check filename first
    std::string filename = path;
    size_t last_slash = path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        filename = path.substr(last_slash + 1);
    }
    // convert filename to lowercase
    std::transform(filename.begin(), filename.end(), filename.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    if (filename.find("hpc") != std::string::npos) return "HPC Cluster";
    if (filename.find("postgres") != std::string::npos || filename.find("postgresql") != std::string::npos) return "PostgreSQL";
    if (filename.find("mysql") != std::string::npos) return "MySQL";
    if (filename.find("mongodb") != std::string::npos || filename.find("mongo") != std::string::npos) return "MongoDB";
    if (filename.find("redis") != std::string::npos) return "Redis";
    if (filename.find("nginx") != std::string::npos) return "Nginx";
    if (filename.find("apache") != std::string::npos || filename.find("httpd") != std::string::npos) return "Apache";
    if (filename.find("auth") != std::string::npos || filename.find("secure") != std::string::npos) return "Security/Auth";
    if (filename.find("cron") != std::string::npos) return "Cron/Scheduler";
    if (filename.find("kernel") != std::string::npos || filename.find("dmesg") != std::string::npos) return "Kernel";
    if (filename.find("bgl") != std::string::npos || filename.find("bluegene") != std::string::npos) return "Supercomputer/BGL";
    if (filename.find("docker") != std::string::npos || filename.find("k8s") != std::string::npos || filename.find("kubernetes") != std::string::npos) return "Container/K8s";
    if (filename.find("firewall") != std::string::npos || filename.find("ufw") != std::string::npos) return "Firewall";
    if (filename.find("dns") != std::string::npos || filename.find("named") != std::string::npos) return "DNS";
    if (filename.find("mail") != std::string::npos || filename.find("postfix") != std::string::npos) return "Email";

    // 2. Check content keywords
    if (memmem_ci(buf, len, "node-", 5) && memmem_ci(buf, len, "subsys", 6)) return "HPC Cluster";
    if (memmem_ci(buf, len, "postgres", 8)) return "PostgreSQL";
    if (memmem_ci(buf, len, "mysql", 5)) return "MySQL";
    if (memmem_ci(buf, len, "redis", 5)) return "Redis";
    if (memmem_ci(buf, len, "mongodb", 7)) return "MongoDB";
    if (memmem_ci(buf, len, "docker", 6) || memmem_ci(buf, len, "kubernetes", 10) || memmem_ci(buf, len, "k8s", 3)) return "Container/K8s";
    if (memmem_ci(buf, len, "sshd", 4) || memmem_ci(buf, len, "pam_unix", 8) || memmem_ci(buf, len, "accepted password", 17)) return "Security/Auth";
    if (memmem_ci(buf, len, "crond", 5) || memmem_ci(buf, len, "scheduler", 9)) return "Cron/Scheduler";
    if (memmem_ci(buf, len, "kernel:", 7) || memmem_ci(buf, len, "dmesg", 5)) return "Kernel";
    if (memmem_ci(buf, len, "bgl", 3) || memmem_ci(buf, len, "r02-m1-n0", 9) || memmem_ci(buf, len, "bluegene", 8)) return "Supercomputer/BGL";
    if (memmem_ci(buf, len, "nginx", 5)) return "Nginx";
    if (memmem_ci(buf, len, "apache", 6)) return "Apache";
    if (memmem_ci(buf, len, "dns", 3) || memmem_ci(buf, len, "query:", 6)) return "DNS";
    if (memmem_ci(buf, len, "postfix", 7) || memmem_ci(buf, len, "sendmail", 8)) return "Email";
    if (memmem_ci(buf, len, "sensor", 6) || memmem_ci(buf, len, "temperature", 11) || memmem_ci(buf, len, "gpu", 3)) return "Sensor/IoT";

    return "";
}

// ─────────────────────────────────────────────────────────────
// Auto-detection: read first 8KB, try each parser on up to 20 lines
// ─────────────────────────────────────────────────────────────

static LogType detectLogType(int fd) {
    char buf[8192];
    ssize_t nread = pread(fd, buf, sizeof(buf), 0);
    if (nread <= 0) return LogType::UNKNOWN;

    // Extract up to 20 lines
    std::vector<std::pair<const char*, size_t>> lines;
    const char* p = buf;
    const char* end = buf + nread;
    while (p < end && lines.size() < 20) {
        const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
        if (!nl) {
            if (end - p > 0) {
                size_t ll = end - p;
                // strip trailing \r
                while (ll > 0 && p[ll-1] == '\r') --ll;
                if (ll > 0) lines.push_back({p, ll});
            }
            break;
        }
        size_t ll = nl - p;
        // strip trailing \r
        while (ll > 0 && p[ll-1] == '\r') --ll;
        if (ll > 0) lines.push_back({p, ll});
        p = nl + 1;
    }

    if (lines.empty()) return LogType::UNKNOWN;

    // Try each parser on each line with a dummy Stats
    struct { LogType type; LineParser parser; int score; } candidates[] = {
        { LogType::NGINX,    parseNginxLine,   0 },
        { LogType::HDFS,     parseHDFSLine,    0 },
        { LogType::SYSLOG,   parseSyslogLine,  0 },
        { LogType::JSON_LOG, parseJsonLine,    0 },
        { LogType::HPC,      parseHPCLine,     0 },
    };

    for (auto& [lptr, llen] : lines) {
        for (auto& c : candidates) {
            Stats dummy;
            if (c.parser(lptr, llen, dummy)) {
                ++c.score;
            }
        }
    }

    // Pick the format with most successful parses
    int bestScore = 0;
    LogType bestType = LogType::UNIVERSAL;
    for (auto& c : candidates) {
        if (c.score > bestScore) {
            bestScore = c.score;
            bestType = c.type;
        }
    }

    return bestType;
}

// ─────────────────────────────────────────────────────────────
// mmap scanner — slides window across file, calls parser
// ─────────────────────────────────────────────────────────────

void analyzeFile(const std::string& path, Stats& stats, LogType& detectedType) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) throw std::runtime_error("Cannot open: " + path);

    struct stat st;
    if (fstat(fd, &st) == -1) { close(fd); throw std::runtime_error("fstat failed"); }
    off_t fileSize = st.st_size;
    if (fileSize == 0) { close(fd); return; }

    // Auto-detect log type
    detectedType = detectLogType(fd);
    std::cerr << "Detected log format: " << logTypeName(detectedType) << "\n";

    // Detect sub-type from filename and content
    {
        char temp_buf[8192];
        ssize_t nread = pread(fd, temp_buf, sizeof(temp_buf), 0);
        if (nread > 0) {
            stats.subType = detectSubLogType(path, temp_buf, nread);
        }
    }

    // Select parser
    LineParser parser = nullptr;
    switch (detectedType) {
        case LogType::NGINX:    parser = parseNginxLine;  break;
        case LogType::HDFS:     parser = parseHDFSLine;   break;
        case LogType::SYSLOG:   parser = parseSyslogLine; break;
        case LogType::JSON_LOG: parser = parseJsonLine;   break;
        case LogType::HPC:      parser = parseHPCLine;    break;
        case LogType::UNIVERSAL:parser = parseUniversalLine; break;
        default:
            // Fall back to trying Nginx
            std::cerr << "Warning: could not detect format, trying Nginx\n";
            parser = parseNginxLine;
            detectedType = LogType::NGINX;
            break;
    }

    const long   pageSize     = sysconf(_SC_PAGESIZE);
    const size_t WINDOW_BYTES = 256ULL * 1024 * 1024; // 256 MB window
    const size_t alignWin     = (WINDOW_BYTES / pageSize) * pageSize;

    off_t  offset    = 0;
    size_t prevTail  = 0;
    std::vector<char> tailBuf(4096);

    std::cerr << "File size: " << (fileSize / 1024 / 1024) << " MB\n";
    std::cerr << "Window:    " << (alignWin  / 1024 / 1024) << " MB\n";

    while (offset < fileSize) {
        size_t remaining = (size_t)(fileSize - offset);
        size_t mapSize   = std::min(alignWin, remaining);

        void* mapped = mmap(nullptr, mapSize, PROT_READ, MAP_PRIVATE, fd, offset);
        if (mapped == MAP_FAILED) {
            close(fd);
            throw std::runtime_error("mmap failed at offset " + std::to_string(offset));
        }
        madvise(mapped, mapSize, MADV_SEQUENTIAL);

        const char* data  = static_cast<const char*>(mapped);
        const char* wend  = data + mapSize;
        const char* lstart = data;

        // If we carried a tail from the previous window, complete that line
        if (prevTail > 0) {
            const char* nl = static_cast<const char*>(memchr(data, '\n', mapSize));
            if (nl) {
                size_t extra = nl - data;
                if (prevTail + extra < tailBuf.size()) {
                    memcpy(tailBuf.data() + prevTail, data, extra);
                    size_t fullLen = prevTail + extra;
                    // Strip trailing \r
                    while (fullLen > 0 && tailBuf[fullLen-1] == '\r') --fullLen;
                    if (fullLen > 0) {
                        if (!parser(tailBuf.data(), fullLen, stats))
                            ++stats.parseErrors;
                    }
                }
                lstart = nl + 1;
            }
            prevTail = 0;
        }

        // Parse all complete lines in this window
        while (lstart < wend) {
            const char* nl = static_cast<const char*>(
                memchr(lstart, '\n', wend - lstart));
            if (!nl) {
                // Incomplete line at end of window — save as tail
                size_t tail = wend - lstart;
                if (tail < tailBuf.size()) {
                    memcpy(tailBuf.data(), lstart, tail);
                    prevTail = tail;
                }
                break;
            }
            size_t lineLen = nl - lstart;
            // Strip trailing \r
            while (lineLen > 0 && lstart[lineLen-1] == '\r') --lineLen;
            if (lineLen > 0) {
                if (!parser(lstart, lineLen, stats))
                    ++stats.parseErrors;
            }
            lstart = nl + 1;
        }

        munmap(mapped, mapSize);
        offset += mapSize;

        int pct = (int)((double)offset / fileSize * 100.0);
        std::cerr << "\rAnalyzing... " << pct << "%" << std::flush;
    }

    // Handle any final tail
    if (prevTail > 0) {
        // Strip trailing \r
        while (prevTail > 0 && tailBuf[prevTail-1] == '\r') --prevTail;
        if (prevTail > 0) {
            if (!parser(tailBuf.data(), prevTail, stats))
                ++stats.parseErrors;
        }
    }

    close(fd);
    std::cerr << "\rAnalyzing... 100%\n";
}

// Variant of analyzeFile that uses a pre-determined type (for --format flag)
void analyzeFileWithType(const std::string& path, Stats& stats, LogType& type) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) throw std::runtime_error("Cannot open: " + path);

    struct stat st;
    if (fstat(fd, &st) == -1) { close(fd); throw std::runtime_error("fstat failed"); }
    off_t fileSize = st.st_size;
    if (fileSize == 0) { close(fd); return; }

    std::cerr << "Forced log format: " << logTypeName(type) << "\n";

    // Detect sub-type from filename and content
    {
        char temp_buf[8192];
        ssize_t nread = pread(fd, temp_buf, sizeof(temp_buf), 0);
        if (nread > 0) {
            stats.subType = detectSubLogType(path, temp_buf, nread);
        }
    }

    // Select parser
    LineParser parser = nullptr;
    switch (type) {
        case LogType::NGINX:    parser = parseNginxLine;  break;
        case LogType::HDFS:     parser = parseHDFSLine;   break;
        case LogType::SYSLOG:   parser = parseSyslogLine; break;
        case LogType::JSON_LOG: parser = parseJsonLine;   break;
        case LogType::HPC:      parser = parseHPCLine;    break;
        case LogType::UNIVERSAL:parser = parseUniversalLine; break;
        default:
            parser = parseUniversalLine;
            type = LogType::UNIVERSAL;
            break;
    }

    const long   pageSize     = sysconf(_SC_PAGESIZE);
    const size_t WINDOW_BYTES = 256ULL * 1024 * 1024;
    const size_t alignWin     = (WINDOW_BYTES / pageSize) * pageSize;

    off_t  offset    = 0;
    size_t prevTail  = 0;
    std::vector<char> tailBuf(4096);

    std::cerr << "File size: " << (fileSize / 1024 / 1024) << " MB\n";

    while (offset < fileSize) {
        size_t remaining = (size_t)(fileSize - offset);
        size_t mapSize   = std::min(alignWin, remaining);

        void* mapped = mmap(nullptr, mapSize, PROT_READ, MAP_PRIVATE, fd, offset);
        if (mapped == MAP_FAILED) {
            close(fd);
            throw std::runtime_error("mmap failed at offset " + std::to_string(offset));
        }
        madvise(mapped, mapSize, MADV_SEQUENTIAL);

        const char* data  = static_cast<const char*>(mapped);
        const char* wend  = data + mapSize;
        const char* lstart = data;

        if (prevTail > 0) {
            const char* nl = static_cast<const char*>(memchr(data, '\n', mapSize));
            if (nl) {
                size_t extra = nl - data;
                if (prevTail + extra < tailBuf.size()) {
                    memcpy(tailBuf.data() + prevTail, data, extra);
                    size_t fullLen = prevTail + extra;
                    while (fullLen > 0 && tailBuf[fullLen-1] == '\r') --fullLen;
                    if (fullLen > 0) {
                        if (!parser(tailBuf.data(), fullLen, stats))
                            ++stats.parseErrors;
                    }
                }
                lstart = nl + 1;
            }
            prevTail = 0;
        }

        while (lstart < wend) {
            const char* nl = static_cast<const char*>(
                memchr(lstart, '\n', wend - lstart));
            if (!nl) {
                size_t tail = wend - lstart;
                if (tail < tailBuf.size()) {
                    memcpy(tailBuf.data(), lstart, tail);
                    prevTail = tail;
                }
                break;
            }
            size_t lineLen = nl - lstart;
            while (lineLen > 0 && lstart[lineLen-1] == '\r') --lineLen;
            if (lineLen > 0) {
                if (!parser(lstart, lineLen, stats))
                    ++stats.parseErrors;
            }
            lstart = nl + 1;
        }

        munmap(mapped, mapSize);
        offset += mapSize;

        int pct = (int)((double)offset / fileSize * 100.0);
        std::cerr << "\rAnalyzing... " << pct << "%" << std::flush;
    }

    if (prevTail > 0) {
        while (prevTail > 0 && tailBuf[prevTail-1] == '\r') --prevTail;
        if (prevTail > 0) {
            if (!parser(tailBuf.data(), prevTail, stats))
                ++stats.parseErrors;
        }
    }

    close(fd);
    std::cerr << "\rAnalyzing... 100%\n";
}

// ─────────────────────────────────────────────────────────────
// Percentile helper
// ─────────────────────────────────────────────────────────────

double percentile(std::vector<uint32_t>& v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    size_t idx = (size_t)(p / 100.0 * (v.size() - 1));
    return v[std::min(idx, v.size()-1)];
}

// ─────────────────────────────────────────────────────────────
// Top-N helper
// ─────────────────────────────────────────────────────────────

template<typename K>
std::vector<std::pair<K, uint64_t>> topN(
    const std::unordered_map<K, uint64_t>& m, size_t n)
{
    std::vector<std::pair<K, uint64_t>> v(m.begin(), m.end());
    std::partial_sort(v.begin(),
                      v.begin() + std::min(n, v.size()),
                      v.end(),
                      [](auto& a, auto& b){ return a.second > b.second; });
    if (v.size() > n) v.resize(n);
    return v;
}

// ─────────────────────────────────────────────────────────────
// Human-readable report to stdout
// ─────────────────────────────────────────────────────────────

void printReport(const Stats& s, LogType type) {
    double errorRate = s.totalRequests > 0
        ? 100.0 * s.errorRequests / s.totalRequests : 0;
    double p50 = 0, p95 = 0, p99 = 0;
    {
        auto lv = s.latencies; // copy for sort
        p50 = percentile(lv, 50);
        p95 = percentile(lv, 95);
        p99 = percentile(lv, 99);
    }

    std::cout << "\n╔══════════════════════════════════════════════╗\n";
    std::cout << "║     LOG ANALYZER — REPORT [" << std::setw(8) << std::left
              << logTypeName(type) << "]       ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n\n";

    std::cout << "── Overview ────────────────────────────────────\n";
    if (!s.subType.empty()) {
        std::cout << "  Log format     : " << logTypeName(type) << " (" << s.subType << ")\n";
    } else {
        std::cout << "  Log format     : " << logTypeName(type) << "\n";
    }
    std::cout << "  Total requests : " << s.totalRequests << "\n";
    std::cout << "  Total bytes    : " << (s.totalBytes / 1024 / 1024) << " MB\n";
    std::cout << "  Error rate     : " << std::fixed << std::setprecision(2)
              << errorRate << "%  ("
              << s.clientErrors << " client, " << s.serverErrors << " server)\n";
    std::cout << "  Parse errors   : " << s.parseErrors << "\n\n";

    std::cout << "── Latency (ms) ────────────────────────────────\n";
    std::cout << "  p50 : " << (int)p50 << " ms\n";
    std::cout << "  p95 : " << (int)p95 << " ms\n";
    std::cout << "  p99 : " << (int)p99 << " ms\n\n";

    std::cout << "── Top 10 IPs ──────────────────────────────────\n";
    for (auto& [ip, cnt] : topN(s.ipCount, 10))
        std::cout << "  " << std::setw(20) << std::left << ip
                  << cnt << " reqs\n";

    std::cout << "\n── Top 10 Endpoints ────────────────────────────\n";
    for (auto& [ep, cnt] : topN(s.endpointCount, 10))
        std::cout << "  " << std::setw(45) << std::left << ep
                  << cnt << " reqs\n";

    std::cout << "\n── Methods / Actions ───────────────────────────\n";
    for (auto& [m, cnt] : topN(s.methodCount, 10))
        std::cout << "  " << std::setw(20) << std::left << m << cnt << "\n";

    std::cout << "\n── Status Codes / Levels ───────────────────────\n";
    for (auto& [st, cnt] : topN(s.statusCount, 15))
        std::cout << "  " << std::setw(10) << std::left << st << cnt << "\n";
}

// ─────────────────────────────────────────────────────────────
// JSON output for dashboard
// ─────────────────────────────────────────────────────────────

std::string escapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

void writeJson(const Stats& s, const std::string& path,
               LogType type, double elapsed) {
    double errorRate = s.totalRequests > 0
        ? 100.0 * s.errorRequests / s.totalRequests : 0;
    auto lv = s.latencies;
    double p50 = percentile(lv, 50);
    double p95 = percentile(lv, 95);
    double p99 = percentile(lv, 99);

    // Build latency histogram (20 buckets)
    std::vector<int> hist(20, 0);
    if (!lv.empty()) {
        uint32_t maxLat = *std::max_element(lv.begin(), lv.end());
        maxLat = std::max(maxLat, (uint32_t)1);
        for (auto l : lv) {
            int b = (int)((double)l / maxLat * 19);
            ++hist[std::min(b, 19)];
        }
    }

    int throughput = (elapsed > 0) ? (int)(s.totalRequests / elapsed) : 0;

    std::ofstream f(path);
    f << std::fixed << std::setprecision(2);
    f << "{\n";
    f << "  \"logType\": \"" << logTypeName(type) << "\",\n";
    if (!s.subType.empty()) {
        f << "  \"subType\": \"" << escapeJson(s.subType) << "\",\n";
    }
    f << "  \"totalRequests\": " << s.totalRequests << ",\n";
    f << "  \"totalBytes\": "    << s.totalBytes    << ",\n";
    f << "  \"errorRate\": "     << errorRate       << ",\n";
    f << "  \"clientErrors\": "  << s.clientErrors  << ",\n";
    f << "  \"serverErrors\": "  << s.serverErrors  << ",\n";
    f << "  \"parseErrors\": "   << s.parseErrors   << ",\n";
    f << "  \"analysisTime\": "  << elapsed         << ",\n";
    f << "  \"throughput\": "    << throughput       << ",\n";
    f << "  \"latency\": { \"p50\": " << (int)p50
      << ", \"p95\": " << (int)p95
      << ", \"p99\": " << (int)p99 << " },\n";

    // Status codes
    f << "  \"statusCodes\": {\n";
    bool first = true;
    for (auto& [st, cnt] : s.statusCount) {
        if (!first) f << ",\n"; first = false;
        f << "    \"" << escapeJson(st) << "\": " << cnt;
    }
    f << "\n  },\n";

    // Top IPs
    f << "  \"topIPs\": [\n";
    first = true;
    for (auto& [ip, cnt] : topN(s.ipCount, 10)) {
        if (!first) f << ",\n"; first = false;
        f << "    { \"ip\": \"" << escapeJson(ip) << "\", \"count\": " << cnt << " }";
    }
    f << "\n  ],\n";

    // Top endpoints
    f << "  \"topEndpoints\": [\n";
    first = true;
    for (auto& [ep, cnt] : topN(s.endpointCount, 10)) {
        if (!first) f << ",\n"; first = false;
        f << "    { \"endpoint\": \"" << escapeJson(ep) << "\", \"count\": " << cnt << " }";
    }
    f << "\n  ],\n";

    // Methods
    f << "  \"methods\": {\n";
    first = true;
    for (auto& [m, cnt] : s.methodCount) {
        if (!first) f << ",\n"; first = false;
        f << "    \"" << escapeJson(m) << "\": " << cnt;
    }
    f << "\n  },\n";

    // Requests per hour
    f << "  \"requestsByHour\": [\n";
    for (int h = 0; h < 24; ++h) {
        auto it = s.hourCount.find(h);
        uint64_t cnt = (it != s.hourCount.end()) ? it->second : 0;
        f << "    " << cnt;
        if (h < 23) f << ",";
        f << "\n";
    }
    f << "  ],\n";

    // Latency histogram
    f << "  \"latencyHistogram\": [";
    for (int i = 0; i < 20; ++i) {
        f << hist[i];
        if (i < 19) f << ",";
    }
    f << "]\n";
    f << "}\n";

    std::cout << "JSON report written to: " << path << "\n";
}

// ─────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <logfile> [-o output.json] [--format nginx|hdfs|syslog|json|hpc|universal]\n";
        return 1;
    }

    std::string logPath;
    std::string jsonPath = "report.json";
    std::string forceFormat;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--format" && i + 1 < argc) {
            forceFormat = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            jsonPath = argv[++i];
        } else if (arg[0] != '-') {
            if (logPath.empty()) {
                logPath = arg;
            } else if (jsonPath == "report.json") {
                // Legacy positional: second non-flag arg is output path
                jsonPath = arg;
            }
        }
    }

    if (logPath.empty()) {
        std::cerr << "Error: no log file specified\n";
        return 1;
    }

    auto t0 = std::chrono::high_resolution_clock::now();

    Stats stats;
    LogType detectedType = LogType::UNKNOWN;

    // If --format is specified, override auto-detection
    if (!forceFormat.empty()) {
        // Convert to lowercase
        std::transform(forceFormat.begin(), forceFormat.end(), forceFormat.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (forceFormat == "nginx" || forceFormat == "apache") {
            detectedType = LogType::NGINX;
        } else if (forceFormat == "hdfs") {
            detectedType = LogType::HDFS;
        } else if (forceFormat == "syslog") {
            detectedType = LogType::SYSLOG;
        } else if (forceFormat == "json") {
            detectedType = LogType::JSON_LOG;
        } else if (forceFormat == "hpc") {
            detectedType = LogType::HPC;
        } else if (forceFormat == "universal" || forceFormat == "auto") {
            detectedType = LogType::UNIVERSAL;
        } else {
            std::cerr << "Warning: unknown format '" << forceFormat << "', using auto-detection\n";
        }
    }

    try {
        if (detectedType != LogType::UNKNOWN) {
            // Format forced via --format flag — skip auto-detection
            analyzeFileWithType(logPath, stats, detectedType);
        } else {
            analyzeFile(logPath, stats, detectedType);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    printReport(stats, detectedType);

    std::cout << "\n── Performance ─────────────────────────────────\n";
    std::cout << "  Analyzed in " << std::fixed << std::setprecision(2)
              << elapsed << " seconds\n";
    if (elapsed > 0)
        std::cout << "  Throughput  : "
                  << (int)(stats.totalRequests / elapsed)
                  << " req/s processed\n";

    writeJson(stats, jsonPath, detectedType, elapsed);
    return 0;
}
