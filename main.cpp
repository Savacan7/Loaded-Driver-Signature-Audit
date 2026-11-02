// ============================================================================
//  ldsa - loaded driver signature audit
//
//  Walks the list of kernel-mode drivers that are loaded on the box right now
//  and, for each one, decides whether its file on disk carries a trusted
//  Authenticode signature. Drivers that do not are surfaced.
//
//  The point of the exercise:
//    A kernel-mode cheat (and a rootkit, and the BYOVD pattern) needs its own
//    driver running in ring 0. On a properly configured machine that driver has
//    to be signed to load at all, so "which drivers are in the kernel and are
//    they all signed?" is a cheap, loud question to ask.
//
//  What this program is and isn't:
//    It reads. It enumerates modules, opens their files, and checks signatures.
//    It writes nothing, loads nothing, and stays out of other processes.
//
//  The detail that separates a real check from a noisy one:
//    Driver files are mostly signed by a detached security catalog (.cat), not
//    by a blob embedded in the .sys. Check only the embedded signature and you
//    will "find" that half of Windows is unsigned. So the trust check mirrors
//    the loader: embedded signature first, security catalog second.
//
//  Toolchain: MSVC, C++17, x64. See build.bat. Elevation helps path resolution.
//  License:   MIT.
// ============================================================================

#ifndef _WIN64
#error "Build as x64."
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <psapi.h>
#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Trust state of a single file. UNKNOWN is kept separate from UNSIGNED on
// purpose: if we cannot read or locate a driver file, we must not pretend it is
// unsigned. A missing answer is never an accusation.
enum class Trust { Unknown, Unsigned, Signed };

struct DriverResult {
    std::wstring name;    // file name only, e.g. ntoskrnl.exe
    std::wstring path;    // resolved Win32 path, if we found it
    Trust        trust = Trust::Unknown;
    std::wstring signer;  // signer common name, if available
    std::wstring note;    // why UNKNOWN, when relevant
    bool         expected = false; // known, benign "no file on disk" case
};

enum class Sev { Pass = 0, Review = 1, Fail = 2 };

// -----------------------------------------------------------------------------
// Driver paths come back in NT/native form (e.g. "\SystemRoot\System32\drivers
// \foo.sys" or "\??\C:\x\foo.sys"). WinVerifyTrust wants a normal Win32 path, so
// translate the common prefixes. If translation yields a path that does not
// exist, the caller treats the driver as UNKNOWN rather than guessing.
// -----------------------------------------------------------------------------
static std::wstring translateNtPath(const std::wstring& in) {
    wchar_t win[MAX_PATH] = {0};
    GetWindowsDirectoryW(win, MAX_PATH);           // e.g. C:\Windows

    auto startsWithI = [](const std::wstring& s, const wchar_t* p) -> bool {
        size_t n = wcslen(p);
        return s.size() >= n && _wcsnicmp(s.c_str(), p, n) == 0;
    };

    if (startsWithI(in, L"\\SystemRoot\\"))
        return std::wstring(win) + L"\\" + in.substr(wcslen(L"\\SystemRoot\\"));
    if (startsWithI(in, L"\\??\\"))
        return in.substr(4);
    if (startsWithI(in, L"\\Windows\\")) {
        // windir without the trailing "\Windows"
        std::wstring w(win);
        size_t slash = w.find_last_of(L'\\');
        std::wstring drive = (slash != std::wstring::npos) ? w.substr(0, slash) : w;
        return drive + in;
    }
    return in; // already a usable path, or something we leave as-is
}

// Pull the signer's display name out of a completed WinVerifyTrust state.
static std::wstring extractSigner(HANDLE hState) {
    if (!hState) return L"";
    CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(hState);
    if (!pd) return L"";
    CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0);
    if (!sgnr || sgnr->csCertChain == 0) return L"";
    PCCERT_CONTEXT cert = sgnr->pasCertChain[0].pCert;
    if (!cert) return L"";
    wchar_t name[256] = {0};
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 256);
    return name;
}

// Embedded Authenticode signature inside the .sys file itself.
static Trust verifyEmbedded(const std::wstring& path, std::wstring& signerOut) {
    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct       = sizeof(wd);
    wd.dwUIChoice     = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   // offline-friendly; we judge the chain, not CRLs
    wd.dwUnionChoice  = WTD_CHOICE_FILE;
    wd.pFile          = &fi;
    wd.dwStateAction  = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags    = WTD_SAFER_FLAG;

    LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);

    Trust result;
    if (st == 0) {
        signerOut = extractSigner(wd.hWVTStateData);
        result = Trust::Signed;
    } else if ((DWORD)st == (DWORD)TRUST_E_NOSIGNATURE) {
        result = Trust::Unsigned;   // caller will still try the catalog
    } else {
        // A signature is present but did not verify (bad digest, untrusted root,
        // expired-without-timestamp, ...). Treat as not trusted.
        result = Trust::Unsigned;
    }

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
    return result;
}

// Catalog (.cat) signature -- how most OS / WHQL drivers are actually signed.
static Trust verifyCatalog(const std::wstring& path, std::wstring& signerOut) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return Trust::Unknown;

    Trust result = Trust::Unsigned;
    HCATADMIN hCat = nullptr;

    // SHA-256 is what modern driver catalogs use.
    if (CryptCATAdminAcquireContext2(&hCat, nullptr, L"SHA256", nullptr, 0) && hCat) {
        DWORD hashLen = 0;
        CryptCATAdminCalcHashFromFileHandle2(hCat, hFile, &hashLen, nullptr, 0);
        if (hashLen > 0) {
            std::vector<BYTE> hash(hashLen);
            if (CryptCATAdminCalcHashFromFileHandle2(hCat, hFile, &hashLen, hash.data(), 0)) {
                // The catalog "member tag" is the uppercase hex of the file hash.
                std::wstring tag;
                tag.reserve(hashLen * 2);
                static const wchar_t* hx = L"0123456789ABCDEF";
                for (DWORD i = 0; i < hashLen; ++i) {
                    tag.push_back(hx[hash[i] >> 4]);
                    tag.push_back(hx[hash[i] & 0xF]);
                }

                HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
                    hCat, hash.data(), hashLen, 0, nullptr);
                if (hCatInfo) {
                    CATALOG_INFO ci = {0};
                    ci.cbStruct = sizeof(ci);
                    if (CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) {
                        WINTRUST_CATALOG_INFO wci = {0};
                        wci.cbStruct            = sizeof(wci);
                        wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                        wci.pcwszMemberTag       = tag.c_str();
                        wci.pcwszMemberFilePath  = path.c_str();
                        wci.hMemberFile          = hFile;
                        wci.pbCalculatedFileHash = hash.data();
                        wci.cbCalculatedFileHash = hashLen;
                        wci.hCatAdmin            = hCat;

                        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                        WINTRUST_DATA wd = {0};
                        wd.cbStruct      = sizeof(wd);
                        wd.dwUIChoice    = WTD_UI_NONE;
                        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                        wd.pCatalog      = &wci;
                        wd.dwStateAction = WTD_STATEACTION_VERIFY;
                        wd.dwProvFlags   = WTD_SAFER_FLAG;

                        LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
                        if (st == 0) {
                            signerOut = extractSigner(wd.hWVTStateData);
                            result = Trust::Signed;
                        }

                        wd.dwStateAction = WTD_STATEACTION_CLOSE;
                        WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &wd);
                    }
                    CryptCATAdminReleaseCatalogContext(hCat, hCatInfo, 0);
                } else {
                    // No catalog claims this hash -> not catalog-signed.
                    result = Trust::Unsigned;
                }
            }
        }
        CryptCATAdminReleaseContext(hCat, 0);
    } else {
        result = Trust::Unknown; // could not even start the catalog check
    }

    CloseHandle(hFile);
    return result;
}

// Verify one driver file: embedded first, then catalog fallback.
static Trust verifyFile(const std::wstring& path, std::wstring& signerOut, std::wstring& noteOut) {
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        noteOut = L"file not found at resolved path";
        return Trust::Unknown;
    }
    std::wstring signer;
    Trust t = verifyEmbedded(path, signer);
    if (t == Trust::Signed) { signerOut = signer; return t; }

    // Not embedded-signed (or embedded signature failed) -> try the catalog.
    std::wstring catSigner;
    Trust ct = verifyCatalog(path, catSigner);
    if (ct == Trust::Signed) { signerOut = catSigner; return ct; }
    if (ct == Trust::Unknown && t == Trust::Unsigned) {
        // Embedded said "no signature", catalog check could not run -> be honest.
        noteOut = L"no embedded signature; catalog check unavailable";
        return Trust::Unknown;
    }
    return Trust::Unsigned;
}

// -----------------------------------------------------------------------------
int main() {
    SetConsoleOutputCP(CP_UTF8);

    // Enumerate loaded kernel driver module bases.
    std::vector<LPVOID> bases(2048);
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)), &needed)) {
        printf("  [!] EnumDeviceDrivers failed (%lu). Run as Administrator.\n", GetLastError());
        return (int)Sev::Review;
    }
    DWORD count = needed / sizeof(LPVOID);
    if (count > bases.size()) {
        bases.resize(count);
        EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)), &needed);
        count = needed / sizeof(LPVOID);
    }

    std::vector<DriverResult> results;
    for (DWORD i = 0; i < count; ++i) {
        wchar_t ntPath[MAX_PATH] = {0};
        wchar_t base[MAX_PATH]   = {0};
        DriverResult r;

        if (GetDeviceDriverFileNameW(bases[i], ntPath, MAX_PATH) > 0) {
            std::wstring win32 = translateNtPath(ntPath);
            r.path = win32;
            r.trust = verifyFile(win32, r.signer, r.note);
        } else {
            r.note = L"could not read driver file name";
        }
        if (GetDeviceDriverBaseNameW(bases[i], base, MAX_PATH) > 0)
            r.name = base;
        else
            r.name = L"<unknown>";

        // The crash-dump stack ("dump_<realdriver>.sys") is cloned into memory by
        // the kernel and has no file on disk by design. Recognize it so a healthy
        // machine is not dragged to REVIEW by an expected, benign absence.
        if (r.trust == Trust::Unknown &&
            r.name.size() >= 5 && _wcsnicmp(r.name.c_str(), L"dump_", 5) == 0) {
            r.expected = true;
            r.note = L"crash-dump stack pseudo-driver (no on-disk file by design)";
        }

        results.push_back(std::move(r));
    }

    // Verdict: any UNSIGNED loaded driver is the headline. UNKNOWNs are reported
    // but only pull the verdict up to REVIEW, never FAIL.
    Sev verdict = Sev::Pass;
    int nSigned = 0, nUnsigned = 0, nUnknown = 0, nExpected = 0;
    for (const auto& r : results) {
        if (r.expected)                 { ++nExpected; continue; }
        if (r.trust == Trust::Signed)   ++nSigned;
        if (r.trust == Trust::Unsigned) ++nUnsigned;
        if (r.trust == Trust::Unknown)  ++nUnknown;
    }
    if (nUnknown > 0 && verdict == Sev::Pass) verdict = Sev::Review;
    if (nUnsigned > 0)                         verdict = Sev::Fail;

    // Output.
    printf("\n  ldsa :: loaded driver signature audit\n\n");
    printf("  %lu drivers loaded  ->  %d signed | %d unsigned | %d unverifiable | %d expected\n\n",
           count, nSigned, nUnsigned, nUnknown, nExpected);

    // Show the drivers that are NOT cleanly signed first -- those are the point.
    auto printOne = [](const DriverResult& r) {
        const char* tag = r.expected                   ? "[expected]"
                        : (r.trust == Trust::Signed)   ? "[signed]  "
                        : (r.trust == Trust::Unsigned) ? "[UNSIGNED]"
                                                       : "[unknown] ";
        printf("    %s %ls\n", tag, r.name.c_str());
        if (!r.path.empty())   printf("               %ls\n", r.path.c_str());
        if (!r.signer.empty()) printf("               signer: %ls\n", r.signer.c_str());
        if (!r.note.empty())   printf("               note: %ls\n", r.note.c_str());
    };

    bool anyFlagged = false;
    for (const auto& r : results)
        if (r.trust != Trust::Signed) { printOne(r); anyFlagged = true; }
    if (anyFlagged) printf("\n");

    printf("  result: ");
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (verdict) {
        case Sev::Pass:
            SetConsoleTextAttribute(hOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            printf("PASS");
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("   all loaded drivers are signed");
            break;
        case Sev::Review:
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            printf("REVIEW");
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf(" a driver could not be verified; this report is partial");
            break;
        case Sev::Fail:
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
            printf("FAIL");
            SetConsoleTextAttribute(hOut, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("   an unsigned kernel driver is loaded");
            break;
    }
    printf("\n\n");

    HWND con = GetConsoleWindow();
    DWORD pid = 0;
    if (con) GetWindowThreadProcessId(con, &pid);
    if (pid == GetCurrentProcessId()) {
        printf("  [enter] to close\n");
        getchar();
    }

    return (int)verdict; // 0 PASS, 1 REVIEW, 2 FAIL
}
