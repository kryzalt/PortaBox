#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <intrin.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <cstdint>
#include <cstdarg>
#include "NetworkSandbox.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" __declspec(dllexport) void IsUltimateASILoader() {}
extern "C" __declspec(dllexport) const wchar_t* GetOverloadPathW();
extern "C" __declspec(dllexport) const char* GetOverloadPathA();





#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3
} KEY_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION {
    ULONG NameLength;
    WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

typedef NTSTATUS (NTAPI *pfn_NtQueryKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

static pfn_NtQueryKey g_NtQueryKey = NULL;





enum MigrationAction {
    ACTION_UNSET = 0,
    ACTION_FRESH = 1,
    ACTION_MOVE = 2,
    ACTION_COPY = 3,
    ACTION_PASSTHROUGH = 4
};

enum LogLevel {
    LOG_LVL_OFF = 0,
    LOG_LVL_FAIL = 1,
    LOG_LVL_ALL = 2,
    LOG_LVL_NET = 3
};

struct CaseInsensitiveLess {
    bool operator()(const std::wstring& a, const std::wstring& b) const {
        return _wcsicmp(a.c_str(), b.c_str()) < 0;
    }
};

struct DecisionEntry {
    std::wstring originalTarget;
    MigrationAction action;
};

struct RegValEntry {
    DWORD type;
    std::vector<uint8_t> data;
};

static std::wstring g_appDir;
static std::wstring g_gameRootDir;
static std::wstring g_portableDir;
static std::wstring g_logFilePath;
static std::wstring g_regFilePath;
static std::wstring g_configFilePath;

static std::map<std::wstring, DecisionEntry, CaseInsensitiveLess> g_fileDecisions;
static std::map<std::wstring, DecisionEntry, CaseInsensitiveLess> g_regDecisions;
static std::map<std::wstring, MigrationAction, CaseInsensitiveLess> g_sessionPrompted;
static std::recursive_mutex g_migrationMutex;

static std::wstring g_realAppDataRoaming;
static std::wstring g_realAppDataLocal;
static std::wstring g_realAppDataLocalLow;
static std::wstring g_realDocuments;
static std::wstring g_realSavedGames;
static std::wstring g_realUserProfile;
static std::wstring g_realProgramData;


static std::wstring g_realAppDataRoamingShort;
static std::wstring g_realAppDataLocalShort;
static std::wstring g_realAppDataLocalLowShort;
static std::wstring g_realDocumentsShort;
static std::wstring g_realSavedGamesShort;
static std::wstring g_realProgramDataShort;
static std::wstring g_realUserProfileShort;
static std::wstring g_realPublicDocuments;
static std::wstring g_realPublicDocumentsShort;

#include <atomic>
#include <dbghelp.h>
#include <winioctl.h>

#pragma comment(lib, "dbghelp.lib")

static std::recursive_mutex g_logMutex;
static thread_local bool g_insideHook = false;
static bool g_enablePlugins = true;
static bool g_enableUpdateFolder = true;
static bool g_enableCrashDumps = false;
int g_logLevel = LOG_LVL_OFF;
static std::wstring g_overloadPathW;
static std::string  g_overloadPathA;


static std::atomic<bool> g_processExiting{ false };
static std::atomic<bool> g_savedOnExit{ false };
static std::atomic<bool> g_oepReached{ false };

typedef LSTATUS (WINAPI *pfn_RegFlushKey)(HKEY);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyA)(HKEY, LPCSTR);
typedef LSTATUS (WINAPI *pfn_RegDeleteValueA)(HKEY, LPCSTR);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyExA)(HKEY, LPCSTR, REGSAM, DWORD);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyValueW)(HKEY, LPCWSTR, LPCWSTR);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyValueA)(HKEY, LPCSTR, LPCSTR);
typedef LPTOP_LEVEL_EXCEPTION_FILTER (WINAPI *pfn_SetUnhandledExceptionFilter)(LPTOP_LEVEL_EXCEPTION_FILTER);

static pfn_RegFlushKey          Orig_RegFlushKey          = NULL;
static pfn_RegDeleteKeyA        Orig_RegDeleteKeyA        = NULL;
static pfn_RegDeleteValueA      Orig_RegDeleteValueA      = NULL;
static pfn_RegDeleteKeyExA      Orig_RegDeleteKeyExA      = NULL;
static pfn_RegDeleteKeyValueW   Orig_RegDeleteKeyValueW   = NULL;
static pfn_RegDeleteKeyValueA   Orig_RegDeleteKeyValueA   = NULL;
static pfn_SetUnhandledExceptionFilter Orig_SetUnhandledExceptionFilter = NULL;


std::string WideToUtf8(const std::wstring& wstr);
void EnsureDirectoryTree(const std::wstring& path, bool isDirectory = false);
bool WriteBufferToFile(const std::wstring& filePath, const std::string& content);
void LogRaw(const std::wstring& msg);
void LogFormat(int minLevel, const wchar_t* fmt, ...);
void LogDetailedStackTrace(const wchar_t* contextHeader, const std::wstring& targetPath);


static std::recursive_mutex g_regMutex;

void SaveRegistryToIni();
void SaveAllConfig();

static void SafeSaveOnExit() {
    bool expected = false;
    if (g_savedOnExit.compare_exchange_strong(expected, true)) {
        SaveRegistryToIni();
        SaveAllConfig();
    }
}




static HMODULE g_hSelfModule = NULL;
static PVOID   g_pVehHandle = NULL;

static std::atomic<bool> g_crashDumpDone{ false };
static std::atomic<bool> g_crashSaveDone{ false };
static std::atomic<bool> g_crashDumpDirReady{ false };

static std::wstring g_crashDumpDir;
static DWORD g_crashThreadId = 0;

static EXCEPTION_RECORD g_crashExceptionRecord = {};
static CONTEXT g_crashContext = {};
static EXCEPTION_POINTERS g_crashExceptionPointers = { &g_crashExceptionRecord, &g_crashContext };

#ifndef STACK_SIZE_PARAM_IS_A_RESERVATION
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000
#endif

struct CrashDumpWork {
    wchar_t DumpPath[32768];
    bool    Success;
    DWORD   Error;
};

static CrashDumpWork g_crashStackOverflowWork = {};

static const wchar_t* ExceptionCodeToString(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return L"ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return L"ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return L"BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return L"DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return L"FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_OVERFLOW:             return L"FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return L"FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return L"FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return L"ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return L"IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return L"INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return L"INT_OVERFLOW";
        case EXCEPTION_PRIV_INSTRUCTION:         return L"PRIV_INSTRUCTION";
        case EXCEPTION_STACK_OVERFLOW:           return L"STACK_OVERFLOW";
        case 0xE06D7363:                         return L"CPP_EXCEPTION (MSVC)";
        default:                                 return L"UNKNOWN_EXCEPTION";
    }
}

static HANDLE CrashCreateFile(const wchar_t* path) {
    if (!path || !*path) {
        return INVALID_HANDLE_VALUE;
    }

    
    
    bool oldInside = g_insideHook;
    g_insideHook = true;

    HANDLE h = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    g_insideHook = oldInside;
    return h;
}

static void CrashEnsureDirectoryTree(const wchar_t* path) {
    if (!path || !*path) {
        return;
    }

    bool oldInside = g_insideHook;
    g_insideHook = true;

    
    
    
    SHCreateDirectoryExW(NULL, path, NULL);

    g_insideHook = oldInside;
}

static EXCEPTION_POINTERS* CrashCopyExceptionPointers(EXCEPTION_POINTERS* info) {
    if (!info) {
        return NULL;
    }

    ZeroMemory(&g_crashExceptionRecord, sizeof(g_crashExceptionRecord));
    ZeroMemory(&g_crashContext, sizeof(g_crashContext));

    if (info->ExceptionRecord) {
        g_crashExceptionRecord = *info->ExceptionRecord;
    }

    if (info->ContextRecord) {
        g_crashContext = *info->ContextRecord;
    }

    g_crashExceptionPointers.ExceptionRecord = info->ExceptionRecord ? &g_crashExceptionRecord : NULL;
    g_crashExceptionPointers.ContextRecord = info->ContextRecord ? &g_crashContext : NULL;

    return &g_crashExceptionPointers;
}

static bool CrashMiniDumpDirect(EXCEPTION_POINTERS* safeInfo, const wchar_t* path, DWORD& error) {
    if (!path || !*path) {
        error = ERROR_INVALID_PARAMETER;
        return false;
    }

    HANDLE hDump = CrashCreateFile(path);
    if (hDump == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        return false;
    }

    MINIDUMP_EXCEPTION_INFORMATION mei;
    mei.ThreadId = g_crashThreadId ? g_crashThreadId : GetCurrentThreadId();
    mei.ExceptionPointers = safeInfo;
    mei.ClientPointers = FALSE;

    
    
    MINIDUMP_TYPE dumpFlags = MiniDumpNormal;

    BOOL ok = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hDump,
        dumpFlags,
        safeInfo ? &mei : NULL,
        NULL,
        NULL
    );

    if (!ok) {
        error = GetLastError();
    } else {
        error = ERROR_SUCCESS;
    }

    CloseHandle(hDump);
    return ok != FALSE;
}

static DWORD WINAPI CrashMiniDumpWorker(LPVOID param) {
    CrashDumpWork* work = (CrashDumpWork*)param;
    if (!work) {
        return 0;
    }

    work->Success = CrashMiniDumpDirect(&g_crashExceptionPointers, work->DumpPath, work->Error);
    return 0;
}

static void CrashWriteTextReport(
    const wchar_t* logPath,
    EXCEPTION_POINTERS* info,
    const wchar_t* dumpPath,
    bool dumpOk,
    DWORD dumpError
) {
    if (!logPath || !*logPath) {
        return;
    }

    wchar_t buf[4096];

    DWORD code = 0;
    void* faultAddr = NULL;

    if (info && info->ExceptionRecord) {
        code = info->ExceptionRecord->ExceptionCode;
        faultAddr = info->ExceptionRecord->ExceptionAddress;
    }

    swprintf_s(buf,
        L"Portable Engine crash report\r\n"
        L"Dump file: %s\r\n"
        L"Dump written: %s\r\n"
        L"LastError: %lu\r\n"
        L"Exception: 0x%08lX (%s)\r\n"
        L"Fault address: %p\r\n"
        L"Crash thread: %lu\r\n",
        dumpPath ? dumpPath : L"",
        dumpOk ? L"yes" : L"no",
        dumpError,
        code,
        ExceptionCodeToString(code),
        faultAddr,
        g_crashThreadId
    );

    HANDLE hLog = CrashCreateFile(logPath);
    if (hLog == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD written = 0;
    WriteFile(hLog, buf, (DWORD)(wcslen(buf) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(hLog);
}

static bool CrashWriteDump(EXCEPTION_POINTERS* info) {
    if (!g_enableCrashDumps) {
        return false;
    }

    bool expected = false;
    if (!g_crashDumpDone.compare_exchange_strong(expected, true)) {
        return false;
    }

    const wchar_t* dir = !g_crashDumpDir.empty() ? g_crashDumpDir.c_str() : L".\\CrashDumps";

    if (!g_crashDumpDirReady.load(std::memory_order_relaxed)) {
        CrashEnsureDirectoryTree(dir);
        g_crashDumpDirReady.store(true, std::memory_order_release);
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t baseName[128];
    swprintf_s(baseName,
        L"Crash_%04d%02d%02d_%02d%02d%02d_%08lX_%08lX",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        GetCurrentProcessId(),
        GetCurrentThreadId()
    );

    wchar_t dumpPath[32768];
    wchar_t logPath[32768];

    swprintf_s(dumpPath, L"%s\\%s.dmp", dir, baseName);
    swprintf_s(logPath,  L"%s\\%s.log", dir, baseName);

    g_crashThreadId = GetCurrentThreadId();

    EXCEPTION_POINTERS* safeInfo = CrashCopyExceptionPointers(info);

    bool ok = false;
    DWORD error = ERROR_GEN_FAILURE;

    if (info && info->ExceptionRecord && info->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
        ZeroMemory(&g_crashStackOverflowWork, sizeof(g_crashStackOverflowWork));
        wcsncpy_s(g_crashStackOverflowWork.DumpPath, dumpPath, _TRUNCATE);

        HANDLE hThread = CreateThread(
            NULL,
            1024 * 1024,
            CrashMiniDumpWorker,
            &g_crashStackOverflowWork,
            STACK_SIZE_PARAM_IS_A_RESERVATION,
            NULL
        );

        if (hThread) {
            WaitForSingleObject(hThread, 10000);
            CloseHandle(hThread);

            ok = g_crashStackOverflowWork.Success;
            error = g_crashStackOverflowWork.Error;
        } else {
            error = GetLastError();

            
            ok = CrashMiniDumpDirect(safeInfo, dumpPath, error);
        }
    } else {
        ok = CrashMiniDumpDirect(safeInfo, dumpPath, error);
    }

    CrashWriteTextReport(logPath, info, dumpPath, ok, error);
    return ok;
}

LONG WINAPI PortableCrashHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    g_processExiting.store(true, std::memory_order_release);

    CrashWriteDump(pExceptionInfo);

    bool isStackOverflow =
        pExceptionInfo &&
        pExceptionInfo->ExceptionRecord &&
        pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW;

    
    
    if (!isStackOverflow) {
        bool expectedSave = false;
        if (g_crashSaveDone.compare_exchange_strong(expectedSave, true)) {
            if (g_regMutex.try_lock()) {
                SaveRegistryToIni();
                g_regMutex.unlock();
            }

            if (g_migrationMutex.try_lock()) {
                SaveAllConfig();
                g_migrationMutex.unlock();
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


LONG WINAPI PortableVectoredHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    if (!pExceptionInfo || !pExceptionInfo->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;

    
    if (code == 0xE06D7363 || 
        code == 0x406D1388 || 
        code == 0x40010006 || 
        code == 0x000006BA || 
        code == EXCEPTION_BREAKPOINT ||
        code == EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool isFatal =
        code == EXCEPTION_ACCESS_VIOLATION ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION ||
        code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED ||
        code == EXCEPTION_DATATYPE_MISALIGNMENT ||
        code == EXCEPTION_STACK_OVERFLOW ||
        code == EXCEPTION_IN_PAGE_ERROR ||
        code == EXCEPTION_PRIV_INSTRUCTION;

    if (!isFatal) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    
    
    
    if (g_enableCrashDumps) {
        CrashWriteDump(pExceptionInfo);
    }

    bool isExiting = g_processExiting.load(std::memory_order_relaxed);

    bool isOurModule = false;
    void* faultAddr = pExceptionInfo->ExceptionRecord->ExceptionAddress;
    HMODULE hMod = NULL;

    if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)faultAddr,
            &hMod) && hMod) {
        if (hMod == g_hSelfModule) {
            isOurModule = true;
        }
    }

    
    
    if (isExiting || isOurModule) {
        PortableCrashHandler(pExceptionInfo);
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI Hook_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
    
    return PortableCrashHandler;
}

struct HookGuard {
    bool prev;
    HookGuard() { prev = g_insideHook; g_insideHook = true; }
    ~HookGuard() { g_insideHook = prev; }
};

std::wstring NormalizeSlashes(std::wstring path) {
    for (auto& ch : path) {
        if (ch == L'/') ch = L'\\';
    }
    return path;
}

std::wstring ToUpper(std::wstring str) {
    std::transform(str.begin(), str.end(), str.begin(), ::towupper);
    return str;
}

bool StartsWithI(const std::wstring& str, const std::wstring& prefix) {
    if (prefix.empty() || str.length() < prefix.length()) return false;
    return _wcsnicmp(str.c_str(), prefix.c_str(), prefix.length()) == 0;
}



bool PathStartsWithI(const std::wstring& path, const std::wstring& prefix) {
    if (prefix.empty() || path.length() < prefix.length()) return false;
    
    
    if (_wcsnicmp(path.c_str(), prefix.c_str(), prefix.length()) != 0) return false;
    
    
    if (path.length() == prefix.length()) return true;
    
    
    if (prefix.back() == L'\\' || prefix.back() == L'/') return true;
    
    
    wchar_t nextChar = path[prefix.length()];
    return (nextChar == L'\\' || nextChar == L'/');
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
    if (size <= 0) return std::string();
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &str[0], size, NULL, NULL);
    return str;
}

extern "C" __declspec(dllexport) const wchar_t* GetOverloadPathW() {
    if (!g_enableUpdateFolder) return L"";
    return g_overloadPathW.c_str();
}

extern "C" __declspec(dllexport) const char* GetOverloadPathA() {
    if (!g_enableUpdateFolder) return "";
    return g_overloadPathA.c_str();
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.length(), NULL, 0);
    if (size <= 0) return std::wstring();
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.length(), &wstr[0], size);
    return wstr;
}





typedef HRESULT (WINAPI *pfn_SHGetKnownFolderPath)(REFKNOWNFOLDERID, DWORD, HANDLE, PWSTR*);
typedef HRESULT (WINAPI *pfn_SHGetFolderPathW)(HWND, int, HANDLE, DWORD, LPWSTR);
typedef HRESULT (WINAPI *pfn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef BOOL    (WINAPI *pfn_SHGetSpecialFolderPathW)(HWND, LPWSTR, int, BOOL);
typedef BOOL    (WINAPI *pfn_SHGetSpecialFolderPathA)(HWND, LPSTR, int, BOOL);

typedef HANDLE  (WINAPI *pfn_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE  (WINAPI *pfn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD   (WINAPI *pfn_GetFileAttributesW)(LPCWSTR);
typedef DWORD   (WINAPI *pfn_GetFileAttributesA)(LPCSTR);
typedef BOOL    (WINAPI *pfn_GetFileAttributesExW)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
typedef HANDLE  (WINAPI *pfn_FindFirstFileW)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef HANDLE  (WINAPI *pfn_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef HANDLE  (WINAPI *pfn_FindFirstFileExW)(LPCWSTR, FINDEX_INFO_LEVELS, LPVOID, FINDEX_SEARCH_OPS, LPVOID, DWORD);
typedef BOOL    (WINAPI *pfn_CreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL    (WINAPI *pfn_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL    (WINAPI *pfn_DeleteFileW)(LPCWSTR);
typedef BOOL    (WINAPI *pfn_DeleteFileA)(LPCSTR);
typedef BOOL    (WINAPI *pfn_RemoveDirectoryW)(LPCWSTR);
typedef BOOL    (WINAPI *pfn_RemoveDirectoryA)(LPCSTR);
typedef BOOL    (WINAPI *pfn_MoveFileW)(LPCWSTR, LPCWSTR);
typedef BOOL    (WINAPI *pfn_MoveFileExW)(LPCWSTR, LPCWSTR, DWORD);
typedef BOOL    (WINAPI *pfn_CopyFileW)(LPCWSTR, LPCWSTR, BOOL);
typedef BOOL    (WINAPI *pfn_CopyFileExW)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
typedef BOOL    (WINAPI *pfn_ReplaceFileW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
typedef BOOL    (WINAPI *pfn_ReplaceFileA)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);

typedef LSTATUS (WINAPI *pfn_RegOpenKeyW)(HKEY, LPCWSTR, PHKEY);
typedef LSTATUS (WINAPI *pfn_RegOpenKeyA)(HKEY, LPCSTR, PHKEY);
typedef LSTATUS (WINAPI *pfn_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *pfn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *pfn_RegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegCloseKey)(HKEY);
typedef LSTATUS (WINAPI *pfn_RegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *pfn_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *pfn_RegDeleteValueW)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyW)(HKEY, LPCWSTR);
typedef LSTATUS (WINAPI *pfn_RegEnumKeyW)(HKEY, DWORD, LPWSTR, DWORD);
typedef LSTATUS (WINAPI *pfn_RegEnumKeyA)(HKEY, DWORD, LPSTR, DWORD);
typedef LSTATUS (WINAPI *pfn_RegEnumKeyExW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *pfn_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *pfn_RegEnumValueW)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegQueryInfoKeyW)(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *pfn_RegQueryInfoKeyA)(HKEY, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME);

typedef DWORD (WINAPI *pfn_GetTempPathW)(DWORD, LPWSTR);
typedef DWORD (WINAPI *pfn_GetTempPathA)(DWORD, LPSTR);
typedef void  (WINAPI *pfn_ExitProcess)(UINT);
typedef BOOL  (WINAPI *pfn_DeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);

static pfn_ExitProcess              Orig_ExitProcess              = NULL;
static pfn_DeviceIoControl          Orig_DeviceIoControl          = NULL;
static pfn_SHGetKnownFolderPath     Orig_SHGetKnownFolderPath     = NULL;
static pfn_SHGetFolderPathW         Orig_SHGetFolderPathW         = NULL;
static pfn_SHGetFolderPathA         Orig_SHGetFolderPathA         = NULL;
static pfn_SHGetSpecialFolderPathW  Orig_SHGetSpecialFolderPathW  = NULL;
static pfn_SHGetSpecialFolderPathA  Orig_SHGetSpecialFolderPathA  = NULL;

static pfn_CreateFileW          Orig_CreateFileW          = NULL;
static pfn_CreateFileA          Orig_CreateFileA          = NULL;
static pfn_GetFileAttributesW   Orig_GetFileAttributesW   = NULL;
static pfn_GetFileAttributesA   Orig_GetFileAttributesA   = NULL;
static pfn_GetFileAttributesExW Orig_GetFileAttributesExW = NULL;
static pfn_FindFirstFileW       Orig_FindFirstFileW       = NULL;
static pfn_FindFirstFileA       Orig_FindFirstFileA       = NULL;
static pfn_FindFirstFileExW     Orig_FindFirstFileExW     = NULL;
static pfn_CreateDirectoryW     Orig_CreateDirectoryW     = NULL;
static pfn_CreateDirectoryA     Orig_CreateDirectoryA     = NULL;
static pfn_DeleteFileW          Orig_DeleteFileW          = NULL;
static pfn_DeleteFileA          Orig_DeleteFileA          = NULL;
static pfn_RemoveDirectoryW     Orig_RemoveDirectoryW     = NULL;
static pfn_RemoveDirectoryA     Orig_RemoveDirectoryA     = NULL;
static pfn_MoveFileW            Orig_MoveFileW            = NULL;
static pfn_MoveFileExW          Orig_MoveFileExW          = NULL;
static pfn_CopyFileW            Orig_CopyFileW            = NULL;
static pfn_CopyFileExW          Orig_CopyFileExW          = NULL;
static pfn_ReplaceFileW         Orig_ReplaceFileW         = NULL;
static pfn_ReplaceFileA         Orig_ReplaceFileA         = NULL;

static pfn_RegOpenKeyW          Orig_RegOpenKeyW          = NULL;
static pfn_RegOpenKeyA          Orig_RegOpenKeyA          = NULL;
static pfn_RegOpenKeyExW        Orig_RegOpenKeyExW        = NULL;
static pfn_RegOpenKeyExA        Orig_RegOpenKeyExA        = NULL;
static pfn_RegCreateKeyExW      Orig_RegCreateKeyExW      = NULL;
static pfn_RegCreateKeyExA      Orig_RegCreateKeyExA      = NULL;
static pfn_RegCloseKey          Orig_RegCloseKey          = NULL;
static pfn_RegQueryValueExW     Orig_RegQueryValueExW     = NULL;
static pfn_RegQueryValueExA     Orig_RegQueryValueExA     = NULL;
static pfn_RegSetValueExW       Orig_RegSetValueExW       = NULL;
static pfn_RegSetValueExA       Orig_RegSetValueExA       = NULL;
static pfn_RegDeleteValueW      Orig_RegDeleteValueW      = NULL;
static pfn_RegDeleteKeyW        Orig_RegDeleteKeyW        = NULL;
static pfn_RegEnumKeyW          Orig_RegEnumKeyW          = NULL;
static pfn_RegEnumKeyA          Orig_RegEnumKeyA          = NULL;
static pfn_RegEnumKeyExW        Orig_RegEnumKeyExW        = NULL;
static pfn_RegEnumKeyExA        Orig_RegEnumKeyExA        = NULL;
static pfn_RegEnumValueW        Orig_RegEnumValueW        = NULL;
static pfn_RegQueryInfoKeyW     Orig_RegQueryInfoKeyW     = NULL;
static pfn_RegQueryInfoKeyA     Orig_RegQueryInfoKeyA     = NULL;

static pfn_GetTempPathW         Orig_GetTempPathW         = NULL;
static pfn_GetTempPathA         Orig_GetTempPathA         = NULL;





void LogRaw(const std::wstring& msg) {
    if (g_logFilePath.empty()) return;
    DWORD savedErr = GetLastError();
    HookGuard guard;
    std::lock_guard<std::recursive_mutex> lock(g_logMutex);

    HANDLE hFile = Orig_CreateFileW ? 
        Orig_CreateFileW(g_logFilePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL) :
        CreateFileW(g_logFilePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeBuf[64];
        swprintf_s(timeBuf, L"[%02d:%02d:%02d.%03d] [TID:%04X] ", 
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentThreadId());
        
        std::string utf8 = WideToUtf8(timeBuf + msg + L"\r\n");
        DWORD written = 0;
        WriteFile(hFile, utf8.data(), (DWORD)utf8.size(), &written, NULL);
        CloseHandle(hFile);
    }
    SetLastError(savedErr);
}

void LogFormat(int minLevel, const wchar_t* fmt, ...) {
    if (g_logFilePath.empty() || g_logLevel == LOG_LVL_OFF) return;

    
    if (g_logLevel == LOG_LVL_NET) {
        
        if (minLevel != LOG_LVL_NET) return;
    } else {
        
        if (minLevel == LOG_LVL_NET) {
            
            if (g_logLevel != LOG_LVL_ALL || !g_logNetwork) return;
        } else {
            
            if (g_logLevel < minLevel) return;
        }
    }

    DWORD savedErr = GetLastError();
    va_list args;
    va_start(args, fmt);
    wchar_t buf[2048];
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    LogRaw(buf);
    SetLastError(savedErr);
}

void EnsureDirectoryTree(const std::wstring& path, bool isDirectory) {
    HookGuard guard;
    if (path.empty()) return;
    std::wstring norm = NormalizeSlashes(path);
    if (!isDirectory) {
        size_t lastSlash = norm.rfind(L'\\');
        if (lastSlash == std::wstring::npos) return;
        norm = norm.substr(0, lastSlash);
    }
    if (norm.length() <= 3) return; 
    SHCreateDirectoryExW(NULL, norm.c_str(), NULL);
}

bool WriteBufferToFile(const std::wstring& filePath, const std::string& content) {
    EnsureDirectoryTree(filePath, false);
    HANDLE hFile = Orig_CreateFileW ?
        Orig_CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL) :
        CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL res = WriteFile(hFile, content.data(), (DWORD)content.size(), &written, NULL);
    CloseHandle(hFile);
    return (res && written == content.size());
}

bool ReadFileToBuffer(const std::wstring& filePath, std::string& content) {
    HANDLE hFile = Orig_CreateFileW ?
        Orig_CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) :
        CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }
    content.resize(size);
    DWORD read = 0;
    BOOL res = ReadFile(hFile, &content[0], size, &read, NULL);
    CloseHandle(hFile);
    return (res && read == size);
}





static size_t GetInstructionLength(const uint8_t* code, bool is64) {
    const uint8_t* p = code;
    uint8_t rex = 0;
    bool op_size_override = false;
    bool addr_size_override = false;

    while (true) {
        uint8_t b = *p;
        if (b == 0x66) { op_size_override = true; p++; }
        else if (b == 0x67) { addr_size_override = true; p++; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x36 || 
                 b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { p++; }
        else if (is64 && (b >= 0x40 && b <= 0x4F)) { rex = b; p++; }
        else break;
    }

    uint8_t op = *p++;
    bool has_modrm = false;
    uint8_t imm_size = 0;

    if (op == 0x0F) {
        uint8_t op2 = *p++;
        if (op2 == 0x1E || op2 == 0x1F || (op2 >= 0x40 && op2 <= 0x4F) || 
            (op2 >= 0x90 && op2 <= 0x9F) || (op2 >= 0x10 && op2 <= 0x17) ||
            (op2 >= 0x28 && op2 <= 0x2F) || (op2 >= 0x50 && op2 <= 0x7F) ||
            op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
            op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC7 ||
            op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB) {
            has_modrm = true;
        } else if (op2 >= 0x80 && op2 <= 0x8F) {
            imm_size = 4;
        } else if (op2 == 0xBA) {
            has_modrm = true;
            imm_size = 1;
        } else if (op2 == 0x38 || op2 == 0x3A) {
            p++;
            has_modrm = true;
            if (op2 == 0x3A) imm_size = 1;
        }
    } else {
        if ((op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) ||
            (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) ||
            (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) ||
            (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) ||
            (op >= 0x80 && op <= 0x83) || (op >= 0x84 && op <= 0x8B) ||
            op == 0x8D || op == 0x8F || op == 0xC6 || op == 0xC7 || op == 0xFF ||
            (op >= 0xD0 && op <= 0xD3) || (op >= 0xF6 && op <= 0xF7) ||
            (op >= 0xC0 && op <= 0xC1) || (is64 && op == 0x63) ||
            op == 0x69 || op == 0x6B) {
            has_modrm = true;
            if (op == 0xC7 || op == 0x69) imm_size = op_size_override ? 2 : 4;
            else if (op == 0xC6 || op == 0x6B || op == 0xC0 || op == 0xC1) imm_size = 1;
            else if (op == 0x81) imm_size = op_size_override ? 2 : 4;
            else if (op == 0x80 || op == 0x82 || op == 0x83) imm_size = 1;
            else if (op == 0xF6) {
                uint8_t modrm = *p;
                if (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1) imm_size = 1;
            } else if (op == 0xF7) {
                uint8_t modrm = *p;
                if (((modrm >> 3) & 7) == 0 || ((modrm >> 3) & 7) == 1) imm_size = op_size_override ? 2 : 4;
            }
        } else if (op >= 0xA0 && op <= 0xA3) {
            imm_size = is64 ? 8 : (addr_size_override ? 2 : 4);
        } else if (op >= 0xB8 && op <= 0xBF) {
            imm_size = is64 && (rex & 8) ? 8 : (op_size_override ? 2 : 4);
        } else if (op >= 0xB0 && op <= 0xB7) {
            imm_size = 1;
        } else if (op == 0xE8 || op == 0xE9) {
            imm_size = 4;
        } else if (op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0xE3) {
            imm_size = 1;
        } else if (op == 0x68) {
            imm_size = op_size_override ? 2 : 4;
        } else if (op == 0x6A || op == 0xA8) {
            imm_size = 1;
        } else if (op == 0xA9) {
            imm_size = op_size_override ? 2 : 4;
        } else if (op == 0xC2) {
            imm_size = 2;
        } else if ((op & 0xC7) == 0x04) {
            imm_size = 1;
        } else if ((op & 0xC7) == 0x05) {
            imm_size = op_size_override ? 2 : 4;
        }
    }

    if (has_modrm) {
        uint8_t modrm = *p++;
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;

        if (!is64 && addr_size_override) {
            if (mod == 1) p += 1;
            else if (mod == 2) p += 2;
            else if (mod == 0 && rm == 6) p += 2;
        } else {
            if (mod != 3 && rm == 4) {
                uint8_t sib = *p++;
                uint8_t base = sib & 7;
                if (mod == 0 && base == 5) p += 4;
            }
            if (mod == 1) p += 1;
            else if (mod == 2) p += 4;
            else if (mod == 0 && (rm == 5 || (is64 && rm == 5))) p += 4;
        }
    }

    p += imm_size;
    return (size_t)(p - code);
}

static const size_t MAX_SUSPENDED_THREADS = 1024;
static DWORD g_suspendedThreadIds[MAX_SUSPENDED_THREADS];
static size_t g_suspendedThreadCount = 0;

static void SuspendOtherThreadsSafe() {
    g_suspendedThreadCount = 0;
    DWORD currentThreadId = GetCurrentThreadId();
    DWORD currentProcessId = GetCurrentProcessId();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == currentProcessId && te.th32ThreadID != currentThreadId) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (SuspendThread(hThread) != (DWORD)-1) {
                        if (g_suspendedThreadCount < MAX_SUSPENDED_THREADS) {
                            g_suspendedThreadIds[g_suspendedThreadCount++] = te.th32ThreadID;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

static void ResumeOtherThreadsSafe() {
    for (size_t i = 0; i < g_suspendedThreadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, g_suspendedThreadIds[i]);
        if (hThread) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
    g_suspendedThreadCount = 0;
}

static void* AllocateTrampolineBufferNear(void* targetAddr, size_t size) {
#if defined(_M_X64) || defined(__x86_64__)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t minAddr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;
    uintptr_t target = (uintptr_t)targetAddr;

    uintptr_t startLow = (target > 0x70000000) ? target - 0x70000000 : minAddr;
    if (startLow < minAddr) startLow = minAddr;
    uintptr_t startHigh = (target + 0x70000000 < maxAddr) ? target + 0x70000000 : maxAddr;
    if (startHigh > maxAddr) startHigh = maxAddr;

    uintptr_t addr = (target > gran) ? (target - gran) : 0;
    while (addr >= startLow && addr <= target) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            void* mem = VirtualAlloc((void*)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem) return mem;
        }
        if ((uintptr_t)mbi.AllocationBase > gran) {
            addr = (uintptr_t)mbi.AllocationBase - gran;
        } else {
            break;
        }
    }

    addr = target + gran;
    while (addr <= startHigh) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            void* mem = VirtualAlloc((void*)addr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem) return mem;
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        addr = (addr + gran - 1) & ~(gran - 1);
    }
    return NULL;
#else
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
}

bool CreateHook(void* targetFunc, void* hookFunc, void** originalTrampoline) {
    if (!targetFunc || !hookFunc || !originalTrampoline) return false;

    uint8_t* pTarget = (uint8_t*)targetFunc;

    for (int depth = 0; depth < 5; depth++) {
        if (pTarget[0] == 0xFF && pTarget[1] == 0x25) {
#if defined(_M_X64) || defined(__x86_64__)
            int32_t rel = *(int32_t*)(pTarget + 2);
            uint8_t* pDest = *(uint8_t**)(pTarget + 6 + rel);
            if (pDest == (uint8_t*)hookFunc) return (*originalTrampoline != NULL);
            if (pDest) { pTarget = pDest; continue; }
#else
            uint8_t** pSlot = *(uint8_t***)(pTarget + 2);
            if (pSlot && *pSlot == (uint8_t*)hookFunc) return (*originalTrampoline != NULL);
            if (pSlot && *pSlot) { pTarget = *pSlot; continue; }
#endif
        }
        if (pTarget[0] == 0xE9) {
            int32_t rel = *(int32_t*)(pTarget + 1);
            uint8_t* dest = pTarget + 5 + rel;
            if (dest == (uint8_t*)hookFunc) return (*originalTrampoline != NULL);
#if defined(_M_X64) || defined(__x86_64__)
            if (dest && dest[0] == 0xFF && dest[1] == 0x25 && *(int32_t*)(dest + 2) == 0) {
                if (*(uint8_t**)(dest + 6) == (uint8_t*)hookFunc) return (*originalTrampoline != NULL);
            }
#endif
            pTarget = dest;
            continue;
        }
        if (pTarget[0] == 0xEB) {
            int8_t rel = *(int8_t*)(pTarget + 1);
            uint8_t* dest = pTarget + 2 + rel;
            if (dest == (uint8_t*)hookFunc) return (*originalTrampoline != NULL);
            pTarget = dest;
            continue;
        }
        break;
    }

    size_t stolenBytes = 0;
    while (stolenBytes < 5) {
#if defined(_M_X64) || defined(__x86_64__)
        size_t len = GetInstructionLength(pTarget + stolenBytes, true);
#else
        size_t len = GetInstructionLength(pTarget + stolenBytes, false);
#endif
        if (len == 0) len = 1;
        stolenBytes += len;
    }

#if defined(_M_X64) || defined(__x86_64__)
    size_t totalAlloc = 256;
    uint8_t* pBlock = (uint8_t*)AllocateTrampolineBufferNear(pTarget, totalAlloc);
    bool isAbsolute14 = false;

    if (!pBlock) {
        stolenBytes = 0;
        while (stolenBytes < 14) {
            size_t len = GetInstructionLength(pTarget + stolenBytes, true);
            if (len == 0) len = 1;
            stolenBytes += len;
        }
        pBlock = (uint8_t*)VirtualAlloc(NULL, totalAlloc, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pBlock) return false;
        isAbsolute14 = true;
    }

    pBlock[0] = 0xFF;
    pBlock[1] = 0x25;
    *(int32_t*)&pBlock[2] = 0;
    *(uint64_t*)&pBlock[6] = (uint64_t)hookFunc;

    uint8_t* pTrampoline = pBlock + 32;
    memcpy(pTrampoline, pTarget, stolenBytes);

    size_t cur = 0;
    while (cur < stolenBytes) {
        size_t len = GetInstructionLength(pTarget + cur, true);
        if (len == 0) len = 1;

        const uint8_t* p = pTarget + cur;
        size_t pfxLen = 0;
        while (true) {
            uint8_t b = *p;
            if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) { p++; pfxLen++; }
            else if (b >= 0x40 && b <= 0x4F) { p++; pfxLen++; }
            else break;
        }

        uint8_t mainOp = *p++;
        if (mainOp == 0xE8 || mainOp == 0xE9) {
            int32_t origRel = *(int32_t*)(pTarget + cur + 1 + pfxLen);
            uint8_t* absTarget = (pTarget + cur + len) + origRel;
            int64_t diff = (int64_t)(absTarget - (pTrampoline + cur + len));
            if (diff < INT32_MIN || diff > INT32_MAX) {
                VirtualFree(pBlock, 0, MEM_RELEASE);
                return false;
            }
            *(int32_t*)(pTrampoline + cur + 1 + pfxLen) = (int32_t)diff;
        } else if (mainOp == 0x0F && (*p >= 0x80 && *p <= 0x8F)) {
            p++;
            int32_t origRel = *(int32_t*)(pTarget + cur + 2 + pfxLen);
            uint8_t* absTarget = (pTarget + cur + len) + origRel;
            int64_t diff = (int64_t)(absTarget - (pTrampoline + cur + len));
            if (diff < INT32_MIN || diff > INT32_MAX) {
                VirtualFree(pBlock, 0, MEM_RELEASE);
                return false;
            }
            *(int32_t*)(pTrampoline + cur + 2 + pfxLen) = (int32_t)diff;
        } else if (mainOp == 0xEB || (mainOp >= 0x70 && mainOp <= 0x7F)) {
            int8_t origRel = *(int8_t*)(pTarget + cur + 1 + pfxLen);
            uint8_t* absTarget = (pTarget + cur + len) + origRel;
            if (absTarget >= pTarget && absTarget < pTarget + stolenBytes) {
                intptr_t diff = (pTrampoline + (absTarget - pTarget)) - (pTrampoline + cur + len);
                *(int8_t*)(pTrampoline + cur + 1 + pfxLen) = (int8_t)diff;
            }
        } else {
            bool hasModRm = false;
            if (mainOp == 0x0F) {
                uint8_t op2 = *p++;
                if (op2 == 0x1E || op2 == 0x1F || (op2 >= 0x40 && op2 <= 0x4F) || 
                    (op2 >= 0x90 && op2 <= 0x9F) || (op2 >= 0x10 && op2 <= 0x17) ||
                    (op2 >= 0x28 && op2 <= 0x2F) || (op2 >= 0x50 && op2 <= 0x7F) ||
                    op2 == 0xAF || op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
                    op2 == 0xB0 || op2 == 0xB1 || op2 == 0xC0 || op2 == 0xC1 || op2 == 0xC7 ||
                    op2 == 0xA3 || op2 == 0xAB || op2 == 0xB3 || op2 == 0xBB || op2 == 0xBA) {
                    hasModRm = true;
                } else if (op2 == 0x38 || op2 == 0x3A) {
                    p++;
                    hasModRm = true;
                }
            } else {
                if ((mainOp >= 0x00 && mainOp <= 0x03) || (mainOp >= 0x08 && mainOp <= 0x0B) ||
                    (mainOp >= 0x10 && mainOp <= 0x13) || (mainOp >= 0x18 && mainOp <= 0x1B) ||
                    (mainOp >= 0x20 && mainOp <= 0x23) || (mainOp >= 0x28 && mainOp <= 0x2B) ||
                    (mainOp >= 0x30 && mainOp <= 0x33) || (mainOp >= 0x38 && mainOp <= 0x3B) ||
                    (mainOp >= 0x80 && mainOp <= 0x8B) || mainOp == 0x8D || mainOp == 0x8F ||
                    mainOp == 0xC6 || mainOp == 0xC7 || mainOp == 0xFF ||
                    (mainOp >= 0xD0 && mainOp <= 0xD3) || (mainOp >= 0xF6 && mainOp <= 0xF7) ||
                    (mainOp >= 0xC0 && mainOp <= 0xC1) || mainOp == 0x63 ||
                    mainOp == 0x69 || mainOp == 0x6B) {
                    hasModRm = true;
                }
            }

            if (hasModRm && p < pTarget + cur + len) {
                uint8_t modrm = *p;
                uint8_t mod = (modrm >> 6) & 3;
                uint8_t rm = modrm & 7;
                if (mod == 0 && rm == 5) {
                    size_t modrmOffset = (size_t)(p - (pTarget + cur));
                    int32_t origDisp = *(int32_t*)(pTarget + cur + modrmOffset + 1);
                    uint8_t* absTarget = (pTarget + cur + len) + origDisp;
                    int64_t diff = (int64_t)(absTarget - (pTrampoline + cur + len));
                    if (diff < INT32_MIN || diff > INT32_MAX) {
                        VirtualFree(pBlock, 0, MEM_RELEASE);
                        return false;
                    }
                    *(int32_t*)(pTrampoline + cur + modrmOffset + 1) = (int32_t)diff;
                }
            }
        }
        cur += len;
    }

    uint8_t* pAfterStolen = pTarget + stolenBytes;
    pTrampoline[stolenBytes] = 0xFF;
    pTrampoline[stolenBytes + 1] = 0x25;
    *(int32_t*)&pTrampoline[stolenBytes + 2] = 0;
    *(uint64_t*)&pTrampoline[stolenBytes + 6] = (uint64_t)pAfterStolen;

    *originalTrampoline = pTrampoline;

    SuspendOtherThreadsSafe();

    DWORD oldProtect;
    VirtualProtect(pTarget, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtect);

    if (isAbsolute14) {
        pTarget[0] = 0xFF;
        pTarget[1] = 0x25;
        *(int32_t*)&pTarget[2] = 0;
        *(uint64_t*)&pTarget[6] = (uint64_t)hookFunc;
        for (size_t i = 14; i < stolenBytes; i++) pTarget[i] = 0x90;
    } else {
        pTarget[0] = 0xE9;
        *(int32_t*)&pTarget[1] = (int32_t)(pBlock - (pTarget + 5));
        for (size_t i = 5; i < stolenBytes; i++) pTarget[i] = 0x90;
    }

    VirtualProtect(pTarget, stolenBytes, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, stolenBytes);
    FlushInstructionCache(GetCurrentProcess(), pBlock, totalAlloc);

    ResumeOtherThreadsSafe();
#else
    size_t trampSize = stolenBytes + 16;
    uint8_t* pTrampoline = (uint8_t*)AllocateTrampolineBufferNear(pTarget, trampSize);
    if (!pTrampoline) return false;

    memcpy(pTrampoline, pTarget, stolenBytes);
    size_t cur = 0;
    while (cur < stolenBytes) {
        size_t len = GetInstructionLength(pTarget + cur, false);
        if (len == 0) len = 1;
        uint8_t op = pTarget[cur];

        if (op == 0xE8 || op == 0xE9) {
            int32_t origRel = *(int32_t*)(pTarget + cur + 1);
            uint8_t* absTarget = (pTarget + cur + 5) + origRel;
            *(int32_t*)(pTrampoline + cur + 1) = (int32_t)(absTarget - (pTrampoline + cur + 5));
        } else if (op == 0xEB) {
            int8_t shortRel = *(int8_t*)(pTarget + cur + 1);
            uint8_t* absTarget = (pTarget + cur + 2) + shortRel;
            intptr_t diff = (intptr_t)absTarget - (intptr_t)(pTrampoline + cur + 2);
            if (diff >= -128 && diff <= 127) {
                pTrampoline[cur + 1] = (uint8_t)(int8_t)diff;
            }
        }
        cur += len;
    }

    uint8_t* pAfterStolen = pTarget + stolenBytes;
    pTrampoline[stolenBytes] = 0xE9;
    *(int32_t*)&pTrampoline[stolenBytes + 1] = (int32_t)(pAfterStolen - (pTrampoline + stolenBytes + 5));

    *originalTrampoline = pTrampoline;

    SuspendOtherThreadsSafe();

    DWORD oldProtect;
    VirtualProtect(pTarget, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
    pTarget[0] = 0xE9;
    *(int32_t*)&pTarget[1] = (int32_t)((uint8_t*)hookFunc - (pTarget + 5));
    for (size_t i = 5; i < stolenBytes; i++) pTarget[i] = 0x90;

    VirtualProtect(pTarget, stolenBytes, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, stolenBytes);
    FlushInstructionCache(GetCurrentProcess(), pTrampoline, trampSize);

    ResumeOtherThreadsSafe();
#endif
    return true;
}





static std::map<std::wstring, std::map<std::wstring, RegValEntry, CaseInsensitiveLess>, CaseInsensitiveLess> g_vRegData;
static std::unordered_map<HKEY, std::wstring> g_trackedRealHandles;

struct FakeHKey {
    std::wstring subKey;
};

static std::unordered_map<HKEY, FakeHKey> g_openHandles;
static uintptr_t g_nextHandleId = 0x90000000;

#define IS_FAKE_HKEY(h) ((uintptr_t)(h) >= 0x90000000 && (uintptr_t)(h) < 0xA0000000)

std::wstring NormalizeRegKey(std::wstring key) {
    for (auto& ch : key) {
        if (ch == L'/') ch = L'\\';
    }
    
    std::wstring clean;
    clean.reserve(key.length());
    bool lastWasSlash = false;
    for (wchar_t ch : key) {
        if (ch == L'\\') {
            if (!lastWasSlash) clean.push_back(L'\\');
            lastWasSlash = true;
        } else {
            clean.push_back(ch);
            lastWasSlash = false;
        }
    }
    while (!clean.empty() && clean.front() == L'\\') clean.erase(clean.begin());
    while (!clean.empty() && clean.back() == L'\\') clean.pop_back();

    size_t pos = 0;
    while ((pos = ToUpper(clean).find(L"\\WOW6432NODE")) != std::wstring::npos) {
        clean.erase(pos, 12);
    }
    if (ToUpper(clean).rfind(L"WOW6432NODE\\", 0) == 0) {
        clean.erase(0, 12);
    }
    return clean;
}

bool ShouldVirtualizeKey(const std::wstring& rawKey) {
    std::wstring fullKey = NormalizeRegKey(rawKey);

    
    if (_wcsicmp(fullKey.c_str(), L"HKCU") == 0 ||
        _wcsicmp(fullKey.c_str(), L"HKLM") == 0 ||
        _wcsicmp(fullKey.c_str(), L"HKCU\\Software") == 0 ||
        _wcsicmp(fullKey.c_str(), L"HKLM\\Software") == 0) {
        return false;
    }

    if (!StartsWithI(fullKey, L"HKCU\\Software\\") && !StartsWithI(fullKey, L"HKLM\\Software\\")) {
        return false;
    }

    
    
    
    std::wstring up = ToUpper(fullKey);
    if (up.find(L"\\VALVE") != std::wstring::npos ||
        up.find(L"\\STEAM") != std::wstring::npos ||
        up.find(L"\\CLASSES") != std::wstring::npos ||
        up.find(L"\\STEAMFIX") != std::wstring::npos ||
        up.find(L"\\EPIC GAMES") != std::wstring::npos) {
        return false;
    }

    
    if (PathStartsWithI(fullKey, L"HKCU\\Software\\Microsoft\\Microsoft Games") ||
        PathStartsWithI(fullKey, L"HKLM\\Software\\Microsoft\\Microsoft Games")) {
        
        if (_wcsicmp(fullKey.c_str(), L"HKCU\\Software\\Microsoft\\Microsoft Games") == 0 ||
            _wcsicmp(fullKey.c_str(), L"HKLM\\Software\\Microsoft\\Microsoft Games") == 0) {
            return false;
        }
        return true;
    }

    static const wchar_t* kSystemBlacklist[] = {
        L"HKCU\\Software\\AMD",
        L"HKLM\\Software\\AMD",
        L"HKCU\\Software\\ATI",
        L"HKLM\\Software\\ATI",
        L"HKCU\\Software\\NVIDIA Corporation",
        L"HKLM\\Software\\NVIDIA Corporation",
        L"HKCU\\Software\\Intel",
        L"HKLM\\Software\\Intel",
        L"HKCU\\Software\\Khronos",
        L"HKLM\\Software\\Khronos",
        L"HKCU\\Software\\Microsoft",
        L"HKLM\\Software\\Microsoft",
        L"HKCU\\Software\\Classes",
        L"HKLM\\Software\\Classes",
        L"HKCU\\Software\\Policies",
        L"HKLM\\Software\\Policies",
        L"HKCU\\Software\\RegisteredApplications",
        L"HKLM\\Software\\RegisteredApplications",
        L"HKCU\\Software\\DirectShow",
        L"HKLM\\Software\\DirectShow",
        L"HKCU\\Software\\ASIO",
        L"HKLM\\Software\\ASIO"
    };

    for (const auto& bl : kSystemBlacklist) {
        if (PathStartsWithI(fullKey, bl)) return false;
    }

    return true;
}


std::wstring GetRegVendorOrAppRoot(const std::wstring& full) {
    std::wstring norm = NormalizeRegKey(full);

    
    
    if (StartsWithI(norm, L"HKLM\\")) {
        return L"";
    }

    
    if (PathStartsWithI(norm, L"HKCU\\Software\\Microsoft\\Microsoft Games")) {
        size_t p = ToUpper(norm).find(L"\\MICROSOFT GAMES\\");
        if (p != std::wstring::npos) {
            size_t p2 = norm.find(L'\\', p + 17); 
            std::wstring appRoot = (p2 != std::wstring::npos) ? norm.substr(0, p2) : norm;
            if (ShouldVirtualizeKey(appRoot)) return appRoot;
        }
        return L"";
    }

    
    size_t s1 = ToUpper(norm).find(L"\\SOFTWARE\\");
    if (s1 != std::wstring::npos) {
        size_t s2 = norm.find(L'\\', s1 + 10);
        if (s2 != std::wstring::npos) {
            std::wstring candidate = norm.substr(0, s2);
            
            if (ShouldVirtualizeKey(candidate)) {
                return candidate;
            }
        }
    }

    return L"";
}
std::wstring RootKeyToString(HKEY hKey) {
    if (hKey == HKEY_CURRENT_USER) return L"HKCU";
    if (hKey == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (hKey == HKEY_CLASSES_ROOT) return L"HKCR";
    if (hKey == HKEY_USERS) return L"HKU";
    if (hKey == HKEY_CURRENT_CONFIG) return L"HKCC";

    if (IS_FAKE_HKEY(hKey)) {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        auto it = g_openHandles.find(hKey);
        if (it != g_openHandles.end()) return it->second.subKey;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        auto it = g_trackedRealHandles.find(hKey);
        if (it != g_trackedRealHandles.end()) return it->second;
    }

    if (g_NtQueryKey) {
        ULONG needed = 0;
        g_NtQueryKey(hKey, KeyNameInformation, NULL, 0, &needed);
        if (needed > sizeof(KEY_NAME_INFORMATION)) {
            std::vector<BYTE> buf(needed + 4, 0);
            if (g_NtQueryKey(hKey, KeyNameInformation, buf.data(), needed, &needed) >= 0) {
                PKEY_NAME_INFORMATION pInfo = (PKEY_NAME_INFORMATION)buf.data();
                std::wstring ntPath(pInfo->Name, pInfo->NameLength / sizeof(WCHAR));

                std::wstring resolved;
                if (StartsWithI(ntPath, L"\\REGISTRY\\MACHINE")) {
                    resolved = L"HKLM" + ntPath.substr(17);
                } else if (StartsWithI(ntPath, L"\\REGISTRY\\USER")) {
                    std::wstring rel = ntPath.substr(14);
                    while (!rel.empty() && rel[0] == L'\\') rel.erase(0, 1);
                    size_t slash = rel.find(L'\\');
                    if (slash != std::wstring::npos) {
                        resolved = L"HKCU" + rel.substr(slash);
                    } else {
                        resolved = L"HKCU";
                    }
                }
                if (!resolved.empty()) {
                    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
                    g_trackedRealHandles[hKey] = resolved;
                    return resolved;
                }
            }
        }
    }

    return L"";
}

bool IsKeyInVirtualReg(const std::wstring& fullKey) {
    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    std::wstring norm = NormalizeRegKey(fullKey);
    if (g_vRegData.find(norm) != g_vRegData.end()) return true;
    
    std::wstring prefix = norm + L"\\";
    for (const auto& kv : g_vRegData) {
        if (StartsWithI(kv.first, prefix)) return true;
    }
    return false;
}

MigrationAction GetEffectiveRegDecision(const std::wstring& fullKey, std::wstring* outMatchedParent = NULL) {
    std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
    std::wstring norm = NormalizeRegKey(fullKey);

    auto it = g_regDecisions.find(norm);
    if (it != g_regDecisions.end()) {
        if (outMatchedParent) *outMatchedParent = it->second.originalTarget;
        return it->second.action;
    }

    auto it2 = g_sessionPrompted.find(norm);
    if (it2 != g_sessionPrompted.end()) {
        if (outMatchedParent) *outMatchedParent = it2->first;
        return it2->second;
    }

    
    for (const auto& pair : g_regDecisions) {
        if (PathStartsWithI(norm, pair.first)) {
            if (outMatchedParent) *outMatchedParent = pair.first;
            return pair.second.action;
        }
    }

    for (const auto& pair : g_sessionPrompted) {
        if (PathStartsWithI(norm, pair.first)) {
            if (outMatchedParent) *outMatchedParent = pair.first;
            return pair.second;
        }
    }

    return ACTION_UNSET;
}

static std::wstring EscapeString(const std::wstring& str) {
    std::wstring out;
    out.reserve(str.length() + 8);
    for (wchar_t ch : str) {
        if (ch == L'\\') out += L"\\\\";
        else if (ch == L'\"') out += L"\\\"";
        else if (ch == L'\r') out += L"\\r";
        else if (ch == L'\n') out += L"\\n";
        else if (ch == L'\t') out += L"\\t";
        else out += ch;
    }
    return out;
}

static std::wstring UnescapeString(const std::wstring& str) {
    std::wstring out;
    out.reserve(str.length());
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == L'\\' && i + 1 < str.length()) {
            wchar_t next = str[++i];
            if (next == L'\\') out += L'\\';
            else if (next == L'\"') out += L'\"';
            else if (next == L'r') out += L'\r';
            else if (next == L'n') out += L'\n';
            else if (next == L't') out += L'\t';
            else { out += L'\\'; out += next; }
        } else {
            out += str[i];
        }
    }
    return out;
}

void SaveRegistryToIni() {
    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    if (g_vRegData.empty() || g_regFilePath.empty()) return;

    std::wstringstream ini;
    for (const auto& keyPair : g_vRegData) {
        ini << L"[" << keyPair.first << L"]\r\n";
        for (const auto& valPair : keyPair.second) {
            std::wstring valName = valPair.first.empty() ? L"@" : valPair.first;
            DWORD type = valPair.second.type;
            const auto& data = valPair.second.data;

            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                std::wstring strVal;
                if (!data.empty()) {
                    strVal.assign((wchar_t*)data.data(), data.size() / sizeof(wchar_t));
                    while (!strVal.empty() && strVal.back() == L'\0') strVal.pop_back();
                }
                std::wstring esc = EscapeString(strVal);
                if (type == REG_EXPAND_SZ) ini << L"\"" << EscapeString(valName) << L"\"=expand:\"" << esc << L"\"\r\n";
                else ini << L"\"" << EscapeString(valName) << L"\"=\"" << esc << L"\"\r\n";
            } else if (type == REG_DWORD && data.size() >= sizeof(DWORD)) {
                DWORD d = *(DWORD*)data.data();
                wchar_t hex[32];
                swprintf_s(hex, L"dword:%08x", d);
                ini << L"\"" << EscapeString(valName) << L"\"=" << hex << L"\r\n";
            } else if (type == REG_QWORD && data.size() >= sizeof(uint64_t)) {
                uint64_t q = *(uint64_t*)data.data();
                wchar_t hex[64];
                swprintf_s(hex, L"qword:%016llx", q);
                ini << L"\"" << EscapeString(valName) << L"\"=" << hex << L"\r\n";
            } else {
                wchar_t prefix[32];
                swprintf_s(prefix, L"hex(%x):", type);
                ini << L"\"" << EscapeString(valName) << L"\"=" << prefix;
                for (size_t i = 0; i < data.size(); i++) {
                    wchar_t byteStr[8];
                    swprintf_s(byteStr, L"%02x%s", data[i], (i + 1 < data.size() ? L"," : L""));
                    ini << byteStr;
                }
                ini << L"\r\n";
            }
        }
        ini << L"\r\n";
    }

    if (!WriteBufferToFile(g_regFilePath, WideToUtf8(ini.str()))) {
        LogFormat(LOG_LVL_FAIL, L"[REG ERROR] Failed to write virtual registry to INI: %s (Error: %lu)", g_regFilePath.c_str(), GetLastError());
    }
}

void LoadRegistryFromIni() {
    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    std::string rawData;
    if (g_regFilePath.empty() || !ReadFileToBuffer(g_regFilePath, rawData)) {
        LogFormat(LOG_LVL_FAIL, L"[REG INFO] Virtual registry INI not found or empty: %s", g_regFilePath.c_str());
        return;
    }

    std::wstring wContent = Utf8ToWide(rawData);
    std::wstringstream ini(wContent);
    std::wstring line, currentKey;

    while (std::getline(ini, line)) {
        while (!line.empty() && (line.back() == L' ' || line.back() == L'\t' || line.back() == L'\r' || line.back() == L'\n')) line.pop_back();
        while (!line.empty() && (line.front() == L' ' || line.front() == L'\t')) line.erase(0, 1);

        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line.front() == L'[' && line.back() == L']') {
            currentKey = NormalizeRegKey(line.substr(1, line.length() - 2));
            g_vRegData[currentKey];
            continue;
        }
        if (currentKey.empty()) continue;

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring rawName = line.substr(0, eq);
        std::wstring rawVal = line.substr(eq + 1);

        if (rawName.front() == L'"' && rawName.back() == L'"' && rawName.length() >= 2) {
            rawName = rawName.substr(1, rawName.length() - 2);
        }
        rawName = UnescapeString(rawName);
        if (rawName == L"@") rawName.clear();

        RegValEntry entry;
        if (rawVal.rfind(L"dword:", 0) == 0) {
            entry.type = REG_DWORD;
            DWORD d = wcstoul(rawVal.c_str() + 6, NULL, 16);
            entry.data.resize(sizeof(DWORD));
            memcpy(entry.data.data(), &d, sizeof(DWORD));
        } else if (rawVal.rfind(L"qword:", 0) == 0) {
            entry.type = REG_QWORD;
            uint64_t q = _wcstoui64(rawVal.c_str() + 6, NULL, 16);
            entry.data.resize(sizeof(uint64_t));
            memcpy(entry.data.data(), &q, sizeof(uint64_t));
        } else if (rawVal.rfind(L"hex", 0) == 0) {
            DWORD regType = REG_BINARY;
            size_t colon = rawVal.find(L':');
            if (colon != std::wstring::npos) {
                if (rawVal.length() > 3 && rawVal[3] == L'(') {
                    regType = wcstoul(rawVal.c_str() + 4, NULL, 16);
                }
                entry.type = regType;
                std::wstringstream ss(rawVal.substr(colon + 1));
                std::wstring byteToken;
                while (std::getline(ss, byteToken, L',')) {
                    if (!byteToken.empty()) {
                        uint8_t b = (uint8_t)wcstoul(byteToken.c_str(), NULL, 16);
                        entry.data.push_back(b);
                    }
                }
            } else {
                LogFormat(LOG_LVL_FAIL, L"[REG PARSE ERROR] Malformed hex entry for value \"%s\" in [%s]", rawName.c_str(), currentKey.c_str());
            }
        } else {
            if (rawVal.rfind(L"expand:", 0) == 0) {
                entry.type = REG_EXPAND_SZ;
                rawVal = rawVal.substr(7);
            } else {
                entry.type = REG_SZ;
            }
            if (rawVal.front() == L'"' && rawVal.back() == L'"' && rawVal.length() >= 2) {
                rawVal = rawVal.substr(1, rawVal.length() - 2);
            }
            std::wstring unesc = UnescapeString(rawVal);
            size_t bytes = (unesc.length() + 1) * sizeof(wchar_t);
            entry.data.resize(bytes);
            memcpy(entry.data.data(), unesc.c_str(), bytes);
        }
        g_vRegData[currentKey][rawName] = entry;
    }
}

bool CopySystemRegTreeToVirtual(HKEY hRoot, const std::wstring& rootName, const std::wstring& subKey) {
    HKEY hKey;
    pfn_RegOpenKeyExW pOpen = Orig_RegOpenKeyExW ? Orig_RegOpenKeyExW : RegOpenKeyExW;
    pfn_RegCloseKey pClose = Orig_RegCloseKey ? Orig_RegCloseKey : RegCloseKey;

    if (pOpen(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    bool success = true;
    std::wstring fullPath = NormalizeRegKey(rootName + (subKey.empty() ? L"" : (L"\\" + subKey)));
    
    DWORD valIndex = 0;
    wchar_t valName[16384];
    DWORD valNameLen = 16384;
    DWORD valType = 0;
    DWORD valDataLen = 0;

    while (true) {
        valNameLen = 16384;
        valDataLen = 0;
        LSTATUS st = RegEnumValueW(hKey, valIndex, valName, &valNameLen, NULL, &valType, NULL, &valDataLen);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) {
            success = false;
            break;
        }

        RegValEntry entry;
        entry.type = valType;
        if (valDataLen > 0) {
            entry.data.resize(valDataLen);
            valNameLen = 16384;
            if (RegEnumValueW(hKey, valIndex, valName, &valNameLen, NULL, &valType, entry.data.data(), &valDataLen) != ERROR_SUCCESS) {
                success = false;
                break;
            }
        }
        g_vRegData[fullPath][valName] = entry;
        valIndex++;
    }

    DWORD subIndex = 0;
    wchar_t subName[512];
    DWORD subNameLen = 512;
    while (success) {
        subNameLen = 512;
        LSTATUS st = RegEnumKeyExW(hKey, subIndex++, subName, &subNameLen, NULL, NULL, NULL, NULL);
        if (st == ERROR_NO_MORE_ITEMS) break;
        if (st != ERROR_SUCCESS) {
            success = false;
            break;
        }
        std::wstring nextSub = subKey.empty() ? subName : (subKey + L"\\" + subName);
        if (!CopySystemRegTreeToVirtual(hRoot, rootName, nextSub)) {
            success = false;
            break;
        }
    }
    pClose(hKey);
    return success;
}





void SaveAllConfig() {
    std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
    if (g_configFilePath.empty()) return;
    std::wstringstream ini;

    ini << L"[General]\r\n";
    ini << L"EnablePlugins=" << (g_enablePlugins ? 1 : 0) << L"\r\n";
    ini << L"EnableUpdateFolder=" << (g_enableUpdateFolder ? 1 : 0) << L"\r\n";
    ini << L"EnableCrashDumps=" << (g_enableCrashDumps ? 1 : 0) << L"\r\n";
    ini << L"LogLevel=" << g_logLevel << L"\r\n\r\n";

	ini << L"[Network]\r\n";
    ini << L"EnableNetwork=" << (g_enableNetwork ? 1 : 0) << L"\r\n"; 
    ini << L"BlockInternet=" << (g_blockInternet ? 1 : 0) << L"\r\n";
    ini << L"LogNetwork=" << (g_logNetwork ? 1 : 0) << L"\r\n";
    ini << L"AllowLocalhost=" << (g_allowLocalhost ? 1 : 0) << L"\r\n\r\n";

    ini << L"[FileMigration]\r\n";
    for (const auto& pair : g_fileDecisions) {
        ini << L"\"" << pair.second.originalTarget << L"\"=" << (int)pair.second.action << L"\r\n";
    }
    ini << L"\r\n[RegMigration]\r\n";
    for (const auto& pair : g_regDecisions) {
        ini << L"\"" << pair.second.originalTarget << L"\"=" << (int)pair.second.action << L"\r\n";
    }
    ini << L"\r\n";

    WriteBufferToFile(g_configFilePath, WideToUtf8(ini.str()));
}

void LoadConfig() {
    g_configFilePath = g_portableDir + L"\\portable_config.ini";
    std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
    g_fileDecisions.clear();
    g_regDecisions.clear();

    std::string rawData;
    if (!ReadFileToBuffer(g_configFilePath, rawData)) {
        
        SaveAllConfig();
        return;
    }

    std::wstring wContent = Utf8ToWide(rawData);
    
    
    if (!wContent.empty() && wContent.front() == 0xFEFF) {
        wContent.erase(0, 1);
    }

    
    auto Trim = [](std::wstring& s) {
        while (!s.empty() && (s.front() == L' ' || s.front() == L'\t' || s.front() == L'\r' || s.front() == L'\n' || s.front() == L'"' || s.front() == 0xFEFF)) s.erase(0, 1);
        while (!s.empty() && (s.back() == L' ' || s.back() == L'\t' || s.back() == L'\r' || s.back() == L'\n' || s.back() == L'"')) s.pop_back();
    };

    
    auto ParseBool = [&](const std::wstring& str, bool defaultVal) -> bool {
        std::wstring s = ToUpper(str);
        if (s == L"1" || s == L"TRUE" || s == L"YES" || s == L"ON") return true;
        if (s == L"0" || s == L"FALSE" || s == L"NO" || s == L"OFF") return false;
        return defaultVal;
    };

    bool foundPluginsKey      = false;
    bool foundLogLevelKey     = false;
    bool foundUpdateFolderKey = false;
    bool foundCrashDumpsKey   = false;
	bool foundEnableNetKey    = false;
    bool foundBlockNetKey     = false;
    bool foundLogNetKey       = false;
    bool foundLocalhostKey    = false;

    std::wstringstream ini(wContent);
    std::wstring line, currentSection;

    while (std::getline(ini, line)) {
        Trim(line);
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

        if (line.front() == L'[' && line.back() == L']') {
            currentSection = ToUpper(line.substr(1, line.length() - 2));
            Trim(currentSection);
            continue;
        }

        size_t eq = line.find(L'=');
        if (eq == std::wstring::npos) continue;

        std::wstring key = line.substr(0, eq);
        std::wstring val = line.substr(eq + 1);
        Trim(key);
        Trim(val);
        key = ToUpper(key);

        
        if (currentSection == L"GENERAL" || currentSection == L"NETWORK" || 
            currentSection == L"PLUGINS" || currentSection == L"LOGGING" || currentSection.empty()) {

            if (key == L"ENABLEPLUGINS" || (currentSection == L"PLUGINS" && (key == L"ENABLED" || key == L"ENABLE"))) {
                g_enablePlugins = ParseBool(val, true);
                foundPluginsKey = true;
            } else if (key == L"ENABLEUPDATEFOLDER" || key == L"OVERLOADFROMFOLDER") {
                g_enableUpdateFolder = ParseBool(val, true);
                foundUpdateFolderKey = true;
            } else if (key == L"ENABLECRASHDUMPS" || key == L"CRASHDUMPS") {
                g_enableCrashDumps = ParseBool(val, false);
                foundCrashDumpsKey = true;
            } else if (key == L"LOGLEVEL" || (currentSection == L"LOGGING" && (key == L"LEVEL" || key == L"LOG"))) {
                g_logLevel = _wtoi(val.c_str());
                if (g_logLevel < 0 || g_logLevel > 3) g_logLevel = LOG_LVL_FAIL; 
                foundLogLevelKey = true;
			} else if (key == L"ENABLENETWORK" || key == L"ENABLENETWORKHOOKS" || (currentSection == L"NETWORK" && key == L"ENABLED")) {
                g_enableNetwork = ParseBool(val, true);
                foundEnableNetKey = true;
            } else if (key == L"BLOCKINTERNET") {
                g_blockInternet = ParseBool(val, false);
                foundBlockNetKey = true;
            } else if (key == L"LOGNETWORK") {
                g_logNetwork = ParseBool(val, false);
                foundLogNetKey = true;
            } else if (key == L"ALLOWLOCALHOST") {
                g_allowLocalhost = ParseBool(val, true);
                foundLocalhostKey = true;
            }
            continue;
        }

        
        if (currentSection == L"FILEMIGRATION" || currentSection == L"REGMIGRATION") {
            int act = _wtoi(val.c_str());
            if (act >= 1 && act <= 4) {
                DecisionEntry entry = { key, (MigrationAction)act };
                if (currentSection == L"FILEMIGRATION") g_fileDecisions[NormalizeSlashes(key)] = entry;
                else if (currentSection == L"REGMIGRATION") g_regDecisions[NormalizeRegKey(key)] = entry;
            }
        }
    }

    
    
    if (!foundPluginsKey || !foundLogLevelKey || !foundUpdateFolderKey || !foundCrashDumpsKey ||
        !foundEnableNetKey || !foundBlockNetKey || !foundLogNetKey || !foundLocalhostKey) {
        SaveAllConfig();
    }
}

void SaveDecision(const std::wstring& target, MigrationAction action, bool isRegistry, bool remember) {
    DecisionEntry entry = { target, action };
    {
        std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
        if (isRegistry) g_regDecisions[target] = entry;
        else g_fileDecisions[NormalizeSlashes(target)] = entry;
    }
    if (remember) SaveAllConfig();
}

bool IsShaderCachePath(const std::wstring& path) {
    std::wstring clean = NormalizeSlashes(path);
    std::wstringstream ss(clean);
    std::wstring token;
    while (std::getline(ss, token, L'\\')) {
        std::wstring up = ToUpper(token);
        if (up == L"DXCACHE" || up == L"D3DSCACHE" || up == L"D3DSCALLCACHE" ||
            up == L"OGLCACHE" || up == L"OGLSHADERS" || up == L"GLCACHE" ||
            up == L"VKCACHE" || up == L"SHADERCACHE" || up == L"GPUCACHE") {
            return true;
        }
    }
    return false;
}

void GetFolderStatsRecursive(const std::wstring& dir, uint64_t& totalBytes, uint32_t& totalFiles) {
    HookGuard guard;
    std::wstring search = NormalizeSlashes(dir) + L"\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE h = Orig_FindFirstFileW ? Orig_FindFirstFileW(search.c_str(), &fd) : FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

            std::wstring sub = NormalizeSlashes(dir) + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                GetFolderStatsRecursive(sub, totalBytes, totalFiles);
            } else {
                ULARGE_INTEGER sz;
                sz.LowPart = fd.nFileSizeLow;
                sz.HighPart = fd.nFileSizeHigh;
                totalBytes += sz.QuadPart;
                totalFiles++;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

std::wstring FormatSize(uint64_t bytes) {
    wchar_t buf[64];
    if (bytes >= 1024ULL * 1024ULL * 1024ULL) swprintf_s(buf, L"%.2f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
    else if (bytes >= 1024ULL * 1024ULL) swprintf_s(buf, L"%.2f MB", (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024ULL) swprintf_s(buf, L"%.2f KB", (double)bytes / 1024.0);
    else swprintf_s(buf, L"%llu Bytes", bytes);
    return buf;
}

bool CopyDirectoryWithProgress(const std::wstring& src, const std::wstring& dst, HWND hProgress, uint32_t totalFiles, uint32_t& copiedFiles) {
    HookGuard guard;
    EnsureDirectoryTree(dst, true);
    std::wstring search = NormalizeSlashes(src) + L"\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE h = Orig_FindFirstFileW ? Orig_FindFirstFileW(search.c_str(), &fd) : FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    bool allSuccess = true;
    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

            std::wstring subSrc = NormalizeSlashes(src) + L"\\" + fd.cFileName;
            std::wstring subDst = NormalizeSlashes(dst) + L"\\" + fd.cFileName;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!CopyDirectoryWithProgress(subSrc, subDst, hProgress, totalFiles, copiedFiles)) {
                    allSuccess = false;
                }
            } else {
                BOOL ok = Orig_CopyFileW ? Orig_CopyFileW(subSrc.c_str(), subDst.c_str(), FALSE)
                                         : CopyFileW(subSrc.c_str(), subDst.c_str(), FALSE);
                if (ok) {
                    copiedFiles++;
                    if (hProgress) {
                        SendMessageW(hProgress, PBM_SETPOS, (WPARAM)copiedFiles, 0);
                    }
                } else {
                    allSuccess = false;
                }

                
                MSG msg;
                while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return allSuccess;
}

bool PurgeDirectoryTree(const std::wstring& path) {
    HookGuard guard;
    std::wstring norm = NormalizeSlashes(path);
    std::wstring search = norm + L"\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE h = Orig_FindFirstFileW ? Orig_FindFirstFileW(search.c_str(), &fd) : FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        
        if (Orig_RemoveDirectoryW) return Orig_RemoveDirectoryW(norm.c_str()) != FALSE;
        return RemoveDirectoryW(norm.c_str()) != FALSE;
    }

    pfn_DeleteFileW pDelete = Orig_DeleteFileW ? Orig_DeleteFileW : DeleteFileW;
    pfn_RemoveDirectoryW pRemoveDir = Orig_RemoveDirectoryW ? Orig_RemoveDirectoryW : RemoveDirectoryW;

    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            std::wstring sub = norm + L"\\" + fd.cFileName;

            
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
                SetFileAttributesW(sub.c_str(), FILE_ATTRIBUTE_NORMAL);
            }

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    PurgeDirectoryTree(sub);
                }
                pRemoveDir(sub.c_str());
            } else {
                pDelete(sub.c_str());
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);

    return pRemoveDir(norm.c_str()) != FALSE;
}

#define IDC_RADIO_FRESH       101
#define IDC_RADIO_MOVE        102
#define IDC_RADIO_COPY        103
#define IDC_RADIO_PASSTHROUGH 104
#define IDC_CHK_REMEMBER      105
#define IDC_BTN_OK            106
#define IDC_BTN_OPEN_PATH     107
#define IDC_PROGRESS_BAR      108
#define IDC_STATUS_TEXT       109
#define IDT_COUNTDOWN_TIMER   201

struct MigrationDialogContext {
    std::wstring detectedLocation;
    std::wstring targetLocation; 
    bool isRegistry;
    uint64_t detectedBytes;
    uint32_t detectedFiles;
    MigrationAction resultAction;
    bool resultRemember;
    int countdownSeconds;
    bool timerActive;
    bool copyPerformed; 
    HWND hBtnOk;
    HWND hProgressBar;
    HWND hStatusText;
};

LRESULT CALLBACK MigrationDialogProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MigrationDialogContext* ctx = (MigrationDialogContext*)GetWindowLongPtrW(hWnd, GWLP_USERDATA);

    switch (msg) {
    case WM_NCCREATE: {
        CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, (LONG_PTR)cs->lpCreateParams);
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    case WM_CREATE: {
        ctx = (MigrationDialogContext*)((CREATESTRUCTW*)lParam)->lpCreateParams;
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        std::wstring header = L"Existing save data or configuration detected on this PC:";
        HWND hText = CreateWindowExW(0, L"STATIC", header.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 10, 500, 18, hWnd, NULL, NULL, NULL);
        SendMessageW(hText, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", ctx->detectedLocation.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY | WS_TABSTOP, 20, 32, 385, 23, hWnd, NULL, NULL, NULL);
        SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND btnOpen = CreateWindowExW(0, L"BUTTON", 
            ctx->isRegistry ? L"Open Regedit" : L"Open Folder",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP, 415, 32, 100, 23, hWnd, (HMENU)IDC_BTN_OPEN_PATH, NULL, NULL);
        SendMessageW(btnOpen, WM_SETFONT, (WPARAM)hFont, TRUE);

        std::wstring statsStr;
        if (ctx->isRegistry) statsStr = L"Location: Windows Registry Key";
        else statsStr = L"Detected payload: " + FormatSize(ctx->detectedBytes) + L" (" + std::to_wstring(ctx->detectedFiles) + L" files)";

        ctx->hStatusText = CreateWindowExW(0, L"STATIC", statsStr.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 58, 495, 18, hWnd, (HMENU)IDC_STATUS_TEXT, NULL, NULL);
        SendMessageW(ctx->hStatusText, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND r1 = CreateWindowExW(0, L"BUTTON", L"1. Start fresh in Portable (Do not copy or delete system data) [Default]",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP | WS_TABSTOP, 20, 80, 500, 20, hWnd, (HMENU)IDC_RADIO_FRESH, NULL, NULL);
        SendMessageW(r1, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(r1, BM_SETCHECK, BST_CHECKED, 0);

        HWND r2 = CreateWindowExW(0, L"BUTTON", L"2. Move all data to Portable and delete from system",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 20, 103, 500, 20, hWnd, (HMENU)IDC_RADIO_MOVE, NULL, NULL);
        SendMessageW(r2, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND r3 = CreateWindowExW(0, L"BUTTON", L"3. Copy all data to Portable (Keep existing files on system)",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 20, 126, 500, 20, hWnd, (HMENU)IDC_RADIO_COPY, NULL, NULL);
        SendMessageW(r3, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND r4 = CreateWindowExW(0, L"BUTTON", L"4. Pass-through (Do not redirect, keep using system directly)",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON, 20, 149, 500, 20, hWnd, (HMENU)IDC_RADIO_PASSTHROUGH, NULL, NULL);
        SendMessageW(r4, WM_SETFONT, (WPARAM)hFont, TRUE);

        HWND chk = CreateWindowExW(0, L"BUTTON", L"Remember my choice for this specific item",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | WS_TABSTOP, 20, 177, 495, 20, hWnd, (HMENU)IDC_CHK_REMEMBER, NULL, NULL);
        SendMessageW(chk, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(chk, BM_SETCHECK, BST_CHECKED, 0);

        ctx->hProgressBar = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 20, 203, 495, 14, hWnd, (HMENU)IDC_PROGRESS_BAR, NULL, NULL);
        SendMessageW(ctx->hProgressBar, PBM_SETRANGE32, 0, (LPARAM)max(1, ctx->detectedFiles));
        SendMessageW(ctx->hProgressBar, PBM_SETPOS, 0, 0);

        ctx->hBtnOk = CreateWindowExW(0, L"BUTTON", L"Apply (7s)",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP, 210, 228, 120, 28, hWnd, (HMENU)IDC_BTN_OK, NULL, NULL);
        SendMessageW(ctx->hBtnOk, WM_SETFONT, (WPARAM)hFont, TRUE);

        ctx->countdownSeconds = 7;
        ctx->timerActive = true;
        SetTimer(hWnd, IDT_COUNTDOWN_TIMER, 1000, NULL);
        break;
    }
    case WM_TIMER: {
        if (!ctx) break;
        if (wParam == IDT_COUNTDOWN_TIMER && ctx->timerActive) {
            ctx->countdownSeconds--;
            if (ctx->countdownSeconds > 0) {
                wchar_t bText[32];
                swprintf_s(bText, L"Apply (%ds)", ctx->countdownSeconds);
                SetWindowTextW(ctx->hBtnOk, bText);
            } else {
                ctx->timerActive = false;
                KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
                SendMessageW(hWnd, WM_COMMAND, MAKEWPARAM(IDC_BTN_OK, BN_CLICKED), (LPARAM)ctx->hBtnOk);
            }
        }
        break;
    }
    case WM_COMMAND: {
        if (!ctx) break;
        WORD ctrlId = LOWORD(wParam);

        if (ctrlId == IDC_RADIO_FRESH || ctrlId == IDC_RADIO_MOVE ||
            ctrlId == IDC_RADIO_COPY || ctrlId == IDC_RADIO_PASSTHROUGH ||
            ctrlId == IDC_CHK_REMEMBER || ctrlId == IDC_BTN_OPEN_PATH) {
            if (ctx->timerActive) {
                ctx->timerActive = false;
                KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
                SetWindowTextW(ctx->hBtnOk, L"Apply");
            }
        }

        if (ctrlId == IDC_BTN_OPEN_PATH) {
            if (ctx->isRegistry) {
                HKEY hReg;
                if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", 0, KEY_WRITE, &hReg) == ERROR_SUCCESS) {
                    RegSetValueExW(hReg, L"LastKey", 0, REG_SZ, (const BYTE*)ctx->detectedLocation.c_str(), (DWORD)(ctx->detectedLocation.length() + 1) * sizeof(wchar_t));
                    RegCloseKey(hReg);
                }
                ShellExecuteW(NULL, L"open", L"regedit.exe", NULL, NULL, SW_SHOWNORMAL);
            } else {
                DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(ctx->detectedLocation.c_str()) : GetFileAttributesW(ctx->detectedLocation.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    ShellExecuteW(NULL, L"open", ctx->detectedLocation.c_str(), NULL, NULL, SW_SHOWNORMAL);
                } else {
                    std::wstring param = L"/select,\"" + ctx->detectedLocation + L"\"";
                    ShellExecuteW(NULL, L"open", L"explorer.exe", param.c_str(), NULL, SW_SHOWNORMAL);
                }
            }
        } else if (ctrlId == IDC_BTN_OK) {
            if (ctx->timerActive) {
                ctx->timerActive = false;
                KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
            }

            if (IsDlgButtonChecked(hWnd, IDC_RADIO_FRESH) == BST_CHECKED) ctx->resultAction = ACTION_FRESH;
            else if (IsDlgButtonChecked(hWnd, IDC_RADIO_MOVE) == BST_CHECKED) ctx->resultAction = ACTION_MOVE;
            else if (IsDlgButtonChecked(hWnd, IDC_RADIO_COPY) == BST_CHECKED) ctx->resultAction = ACTION_COPY;
            else if (IsDlgButtonChecked(hWnd, IDC_RADIO_PASSTHROUGH) == BST_CHECKED) ctx->resultAction = ACTION_PASSTHROUGH;

            ctx->resultRemember = (IsDlgButtonChecked(hWnd, IDC_CHK_REMEMBER) == BST_CHECKED);

            
            if (!ctx->isRegistry && (ctx->resultAction == ACTION_MOVE || ctx->resultAction == ACTION_COPY) && !ctx->targetLocation.empty()) {
                EnableWindow(ctx->hBtnOk, FALSE);
                SetWindowTextW(ctx->hStatusText, L"Copying files, please wait...");
                SendMessageW(ctx->hProgressBar, PBM_SETRANGE32, 0, (LPARAM)max(1, ctx->detectedFiles));
                SendMessageW(ctx->hProgressBar, PBM_SETPOS, 0, 0);

                uint32_t copied = 0;
                DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(ctx->detectedLocation.c_str()) : GetFileAttributesW(ctx->detectedLocation.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    bool copySuccess = CopyDirectoryWithProgress(ctx->detectedLocation, ctx->targetLocation, ctx->hProgressBar, ctx->detectedFiles, copied);
                    
                    if (copySuccess && ctx->resultAction == ACTION_MOVE) {
                        SetWindowTextW(ctx->hStatusText, L"Removing system originals...");
                        UpdateWindow(hWnd);
                        PurgeDirectoryTree(ctx->detectedLocation);
                    }
                } else {
                    EnsureDirectoryTree(ctx->targetLocation, false);
                    
                    SetFileAttributesW(ctx->detectedLocation.c_str(), FILE_ATTRIBUTE_NORMAL);
                    BOOL ok = Orig_CopyFileW ? Orig_CopyFileW(ctx->detectedLocation.c_str(), ctx->targetLocation.c_str(), FALSE)
                                             : CopyFileW(ctx->detectedLocation.c_str(), ctx->targetLocation.c_str(), FALSE);
                    if (ok && ctx->resultAction == ACTION_MOVE) {
                        if (Orig_DeleteFileW) Orig_DeleteFileW(ctx->detectedLocation.c_str());
                        else DeleteFileW(ctx->detectedLocation.c_str());
                    }
                }
                ctx->copyPerformed = true;
            }

            DestroyWindow(hWnd);
        }
        break;
    }
    case WM_CLOSE:
        if (ctx) {
            if (ctx->timerActive) {
                ctx->timerActive = false;
                KillTimer(hWnd, IDT_COUNTDOWN_TIMER);
            }
            ctx->resultAction = ACTION_FRESH;
        }
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        PostMessageW(NULL, WM_NULL, 0, 0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

struct MigrationThreadParam {
    MigrationDialogContext* ctx;
};

static DWORD WINAPI MigrationDialogThreadProc(LPVOID lpParam) {
    MigrationThreadParam* p = (MigrationThreadParam*)lpParam;
    MigrationDialogContext* ctx = p->ctx;

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = MigrationDialogProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"PortableEngineMigrationWnd";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    RegisterClassExW(&wc);

    int w = 550, h = 310;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    HWND hWnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        wc.lpszClassName,
        L"Portable Engine - Storage Migration",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        x, y, w, h,
        NULL, NULL, wc.hInstance, ctx
    );

    if (hWnd) {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(hWnd);
        SetActiveWindow(hWnd);

        
        
        MSG msg;
        while (IsWindow(hWnd) && GetMessageW(&msg, NULL, 0, 0)) {
            if (msg.message == WM_QUIT) {
                break;
            }
            if (!IsDialogMessageW(hWnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    return 0;
}

MigrationAction PromptUserMigrationDialog(const std::wstring& detectedPath, const std::wstring& targetPath = L"", bool isRegistry = false, bool* outCopyPerformed = NULL) {
	if (!g_oepReached.load(std::memory_order_relaxed) || g_processExiting.load(std::memory_order_relaxed)) {
        LogFormat(LOG_LVL_FAIL, L"[DIALOG SUPPRESSED] Suppressed migration dialog for \"%s\" during init (Default: FRESH)", detectedPath.c_str());
        return ACTION_FRESH;
    }
    MigrationDialogContext ctx;
    ctx.detectedLocation = detectedPath;
    ctx.targetLocation = targetPath;
    ctx.isRegistry = isRegistry;
    ctx.detectedBytes = 0;
    ctx.detectedFiles = 0;
    ctx.resultAction = ACTION_FRESH;
    ctx.resultRemember = true;
    ctx.countdownSeconds = 7;
    ctx.timerActive = true;
    ctx.copyPerformed = false;

    if (!isRegistry) {
        DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(detectedPath.c_str()) : GetFileAttributesW(detectedPath.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) {
            if (attr & FILE_ATTRIBUTE_DIRECTORY) {
                GetFolderStatsRecursive(detectedPath, ctx.detectedBytes, ctx.detectedFiles);
            } else {
                WIN32_FILE_ATTRIBUTE_DATA fad;
                pfn_GetFileAttributesExW pEx = Orig_GetFileAttributesExW ? Orig_GetFileAttributesExW : GetFileAttributesExW;
                if (pEx(detectedPath.c_str(), GetFileExInfoStandard, &fad)) {
                    ULARGE_INTEGER sz;
                    sz.LowPart = fad.nFileSizeLow; sz.HighPart = fad.nFileSizeHigh;
                    ctx.detectedBytes = sz.QuadPart;
                    ctx.detectedFiles = 1;
                }
            }
        }
    }

    MigrationThreadParam param;
    param.ctx = &ctx;

    
    HANDLE hThread = CreateThread(NULL, 0, MigrationDialogThreadProc, &param, 0, NULL);
    if (hThread) {
        
        
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    if (outCopyPerformed) *outCopyPerformed = ctx.copyPerformed;
    SaveDecision(detectedPath, ctx.resultAction, isRegistry, ctx.resultRemember);
    return ctx.resultAction;
}


inline MigrationAction PromptUserMigrationDialog(const std::wstring& detectedPath, bool isRegistry) {
    return PromptUserMigrationDialog(detectedPath, L"", isRegistry, NULL);
}





bool HasDirectFilesInDirectory(const std::wstring& dir) {
    HookGuard guard;
    std::wstring search = NormalizeSlashes(dir) + L"\\*.*";
    WIN32_FIND_DATAW fd;
    HANDLE h = Orig_FindFirstFileW ? Orig_FindFirstFileW(search.c_str(), &fd) : FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    do {
        if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                if ((fd.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) ||
                    _wcsicmp(fd.cFileName, L"desktop.ini") == 0 ||
                    _wcsicmp(fd.cFileName, L"thumbs.db") == 0 ||
                    _wcsicmp(fd.cFileName, L".DS_Store") == 0) {
                    continue;
                }
                found = true;
                break;
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return found;
}

bool IsPathNotEmpty(const std::wstring& path) {
    HookGuard guard;
    DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(path.c_str()) : GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        std::wstring search = NormalizeSlashes(path) + L"\\*.*";
        WIN32_FIND_DATAW fd;
        HANDLE h = Orig_FindFirstFileW ? Orig_FindFirstFileW(search.c_str(), &fd) : FindFirstFileW(search.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return false;
        bool hasItems = false;
        do {
            if (wcscmp(fd.cFileName, L".") != 0 && wcscmp(fd.cFileName, L"..") != 0) {
                hasItems = true;
                break;
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        return hasItems;
    }
    return true;
}

MigrationAction CheckAndHandleFolderMigration(const std::wstring& realFolder, const std::wstring& portFolder) {
	
	std::wstring normReal = NormalizeSlashes(realFolder);
    if (!g_appDir.empty()) {
        std::wstring normApp = NormalizeSlashes(g_appDir);
        if (PathStartsWithI(normReal, normApp) || PathStartsWithI(normApp, normReal)) {
            return ACTION_FRESH;
        }
    }
    if (!g_gameRootDir.empty()) {
        std::wstring normRoot = NormalizeSlashes(g_gameRootDir);
        if (PathStartsWithI(normReal, normRoot) || PathStartsWithI(normRoot, normReal)) {
            return ACTION_FRESH;
        }
    }
	
    MigrationAction act = ACTION_UNSET;
    {
        std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
        auto it = g_fileDecisions.find(NormalizeSlashes(realFolder));
        if (it != g_fileDecisions.end()) act = it->second.action;
        else {
            auto it2 = g_sessionPrompted.find(NormalizeSlashes(realFolder));
            if (it2 != g_sessionPrompted.end()) act = it2->second;
        }
    }

    bool realHasData = IsPathNotEmpty(realFolder);
    bool portHasData = IsPathNotEmpty(portFolder);

    if (!realHasData) return ACTION_FRESH;

    bool copyAlreadyDone = false;
    if (act == ACTION_UNSET) {
        if (!portHasData) {
            
            LogDetailedStackTrace(L"MIGRATION DIALOG TRIGGERED", realFolder);

            {
                std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
                g_sessionPrompted[NormalizeSlashes(realFolder)] = ACTION_FRESH;
            }
            act = PromptUserMigrationDialog(realFolder, portFolder, false, &copyAlreadyDone);
            {
                std::lock_guard<std::recursive_mutex> lock(g_migrationMutex);
                g_sessionPrompted[NormalizeSlashes(realFolder)] = act;
            }
        } else {
            act = ACTION_FRESH;
        }
    }

    
    if (!copyAlreadyDone) {
        if (act == ACTION_MOVE && !IsPathNotEmpty(portFolder) && realHasData) {
            LogFormat(LOG_LVL_ALL, L"[MIGRATION] Moving to Portable: %s -> %s", realFolder.c_str(), portFolder.c_str());
            DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(realFolder.c_str()) : GetFileAttributesW(realFolder.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                uint32_t copied = 0;
                bool copySuccess = CopyDirectoryWithProgress(realFolder, portFolder, NULL, 0, copied);
                if (copySuccess) {
                    PurgeDirectoryTree(realFolder);
                }
            } else {
                EnsureDirectoryTree(portFolder, false);
                BOOL ok = Orig_CopyFileW ? Orig_CopyFileW(realFolder.c_str(), portFolder.c_str(), FALSE)
                                         : CopyFileW(realFolder.c_str(), portFolder.c_str(), FALSE);
                if (ok) {
                    if (Orig_DeleteFileW) Orig_DeleteFileW(realFolder.c_str());
                    else DeleteFileW(realFolder.c_str());
                }
            }
        } else if (act == ACTION_COPY && !IsPathNotEmpty(portFolder) && realHasData) {
            LogFormat(LOG_LVL_ALL, L"[MIGRATION] Copying to Portable: %s -> %s", realFolder.c_str(), portFolder.c_str());
            DWORD attr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(realFolder.c_str()) : GetFileAttributesW(realFolder.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                uint32_t copied = 0;
                CopyDirectoryWithProgress(realFolder, portFolder, NULL, 0, copied);
            } else {
                EnsureDirectoryTree(portFolder, false);
                if (Orig_CopyFileW) Orig_CopyFileW(realFolder.c_str(), portFolder.c_str(), FALSE);
                else CopyFileW(realFolder.c_str(), portFolder.c_str(), FALSE);
            }
        }
    }

    if (act == ACTION_FRESH) {
        EnsureDirectoryTree(portFolder, true);
    }

    return act;
}







void LogDetailedStackTrace(const wchar_t* contextHeader, const std::wstring& targetPath) {
    void* callStack[32];
    USHORT frames = RtlCaptureStackBackTrace(1, 32, callStack, NULL);
    if (frames == 0) return;

    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);

    std::wstringstream ss;
    ss << L"\r\n==================== [DEBUG CALL STACK DUMP] ====================\r\n";
    ss << L"EVENT:       " << contextHeader << L"\r\n";
    ss << L"TARGET PATH: " << targetPath << L"\r\n";
    ss << L"THREAD ID:   0x" << std::hex << GetCurrentThreadId() << std::dec << L"\r\n";
    ss << L"-----------------------------------------------------------------";
    LogRaw(ss.str());

    for (USHORT i = 0; i < frames; i++) {
        void* addr = callStack[i];
        HMODULE hMod = NULL;
        wchar_t modPath[MAX_PATH] = L"UNKNOWN_MODULE";
        uintptr_t offset = 0;
        const wchar_t* category = L"[UNKNOWN]";

        if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)addr, &hMod) && hMod) {
            
            GetModuleFileNameW(hMod, modPath, MAX_PATH);
            offset = (uintptr_t)addr - (uintptr_t)hMod;

            if ((!g_gameRootDir.empty() && PathStartsWithI(modPath, g_gameRootDir)) ||
                (!g_appDir.empty() && PathStartsWithI(modPath, g_appDir))) {
                category = L"[GAME]  ";
            } else if (PathStartsWithI(modPath, winDir)) {
                category = L"[SYSTEM]";
            } else {
                category = L"[OTHER] ";
            }
        }

        wchar_t line[1024];
        swprintf_s(line, L"  #%02u %s 0x%p (%s + 0x%IX)", 
            i, category, addr, PathFindFileNameW(modPath), offset);
        LogRaw(line);
    }

    LogRaw(L"=================================================================\r\n");
}

bool IsOperationInitiatedByGame(); 


static bool IsCallerSteamFix(void* returnAddr) {
    if (!returnAddr) return false;
    HMODULE hMod = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)returnAddr, &hMod) && hMod) {
        
        
        
        if (hMod == g_hSelfModule) {
            return false;
        }

        wchar_t modPath[MAX_PATH];
        if (GetModuleFileNameW(hMod, modPath, MAX_PATH)) {
            std::wstring name = ToUpper(PathFindFileNameW(modPath));

            
            if (name == L"STEAMFIX64.DLL" || name == L"STEAMFIX.DLL" || 
                name.find(L"ONLINEFIX") != std::wstring::npos ||
                name.find(L"FREETP") != std::wstring::npos ||
                name.find(L"STEAM_API") != std::wstring::npos) {
                return true;
            }

            
            wchar_t sysDir[MAX_PATH];
            GetSystemDirectoryW(sysDir, MAX_PATH);
            bool isSystemDll = PathStartsWithI(modPath, sysDir);

            
            if (!isSystemDll) {
                if (name == L"WINMM.DLL" || name == L"VERSION.DLL" || 
                    name == L"DWMAPI.DLL" || name == L"MSCOREE.DLL" || 
                    name == L"D3D9.DLL" || name == L"DXGI.DLL") {
                    return true; 
                }
            }
        }
    }
    return false;
}


static bool IsDirectCallerFromGame(void* returnAddr) {
    if (!returnAddr) return false;
    HMODULE hMod = NULL;
    if (!GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCWSTR)returnAddr, &hMod) || !hMod) {
        return false;
    }

    
    if (hMod == g_hSelfModule) return true;

    wchar_t modPath[MAX_PATH] = { 0 };
    if (!GetModuleFileNameW(hMod, modPath, MAX_PATH)) return false;

    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);

    bool isGameModule = (!g_gameRootDir.empty() && PathStartsWithI(modPath, g_gameRootDir)) ||
                        (!g_appDir.empty() && PathStartsWithI(modPath, g_appDir));
    bool isWinModule  = PathStartsWithI(modPath, winDir);

    
    if (!isGameModule && !isWinModule) {
        return false;
    }

    
    
    
    return IsOperationInitiatedByGame();
}

bool IsOperationInitiatedByGame() {
    void* callStack[64];
    USHORT frames = RtlCaptureStackBackTrace(1, 64, callStack, NULL);
    if (frames == 0) {
        return false;
    }

    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);

    struct FrameInfo {
        bool isGame;
        bool isSystem;
    };

    std::vector<FrameInfo> stack;
    stack.reserve(frames);

    for (USHORT i = 0; i < frames; i++) {
        void* addr = callStack[i];
        HMODULE hMod = NULL;
        if (GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)addr, &hMod) && hMod) {

            if (hMod == g_hSelfModule) continue;

            wchar_t modPath[MAX_PATH];
            if (GetModuleFileNameW(hMod, modPath, MAX_PATH)) {
                bool isGame = (!g_gameRootDir.empty() && PathStartsWithI(modPath, g_gameRootDir)) ||
                              (!g_appDir.empty() && PathStartsWithI(modPath, g_appDir));
                bool isSystem = PathStartsWithI(modPath, winDir);

                stack.push_back({ isGame, isSystem });
            }
        }
    }

    if (stack.empty()) return false;

    
    
    
    
    size_t startIndex = 0;
    if (stack[0].isGame && stack.size() > 1 && !stack[1].isGame) {
        startIndex = 1;
    }

    USHORT externalFramesCascade = 0;

    for (size_t i = startIndex; i < stack.size(); i++) {
        if (stack[i].isGame) {
            
            
            
            return (externalFramesCascade < 2);
        }

        externalFramesCascade++;
        if (externalFramesCascade >= 2) {
            
            return false;
        }
    }

    
    return false;
}

static bool IsGenericContainerFolder(const std::wstring& name) {
    std::wstring up = ToUpper(name);
    
    return (up == L"MY GAMES" || up == L"SAVED GAMES" || up == L"GAMES");
}

static bool IsServiceDirectoryName(const std::wstring& name) {
    std::wstring up = ToUpper(name);
    return (up == L"SAVES" || up == L"SAVE" || up == L"SAVEGAMES" || up == L"SAVEDATA" ||
            up == L"PROFILES" || up == L"PROFILE" || up == L"SETTINGS" || up == L"CONFIG" ||
            up == L"CONFIGURATION" || up == L"SCREENSHOTS" || up == L"DATA" || up == L"LOGS" ||
            up == L"LOG" || up == L"CACHE" || up == L"SHADERCACHE" || up == L"DUMPS" ||
            up == L"CRASHDUMPS" || up == L"USERS" || up == L"USER" || up == L"PLAYERS" ||
            up == L"PLAYER" || up == L"REMOTE" || up == L"STORAGE" || up == L"SLOTS" ||
            up == L"SLOT" || up == L"TEMP" || up == L"MAIN");
}

static bool IsLikelyFileComponent(const std::wstring& fullPath, const std::wstring& partName, bool isLastPart) {
    pfn_GetFileAttributesW pGetAttr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW : GetFileAttributesW;
    DWORD attr = pGetAttr(fullPath.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES) {
        return !(attr & FILE_ATTRIBUTE_DIRECTORY);
    }

    
    if (!isLastPart) return false;

    
    size_t dot = partName.rfind(L'.');
    if (dot != std::wstring::npos && dot > 0 && dot + 1 < partName.length()) {
        std::wstring ext = partName.substr(dot + 1);
        
        if (ext.length() <= 5 && ext.find(L' ') == std::wstring::npos) {
            
            
            for (wchar_t ch : ext) {
                if (iswalpha(ch)) return true;
            }
        }
    }
    return false;
}

MigrationAction InspectPathAndMigrate(const std::wstring& relativePath, const std::wstring& realBase, const std::wstring& portBase) {
    if (relativePath.empty() || realBase.empty() || portBase.empty()) return ACTION_FRESH;

    std::wstring clean = NormalizeSlashes(relativePath);
    while (!clean.empty() && (clean[0] == L'\\')) clean.erase(0, 1);
    if (clean.empty()) return ACTION_FRESH;

    
    if (!IsOperationInitiatedByGame()) {
        return ACTION_FRESH;
    }

    
    if (StartsWithI(clean, L"Temp")) {
        return ACTION_FRESH;
    }

    std::vector<std::wstring> parts;
    std::wstringstream ss(clean);
    std::wstring item;
    while (std::getline(ss, item, L'\\')) {
        if (!item.empty()) parts.push_back(item);
    }
    if (parts.empty()) return ACTION_FRESH;

    
    std::wstring candidate;
    
    bool isDocsOrSaves = (!g_realDocuments.empty() && PathStartsWithI(realBase, g_realDocuments)) ||
                         (!g_realPublicDocuments.empty() && PathStartsWithI(realBase, g_realPublicDocuments)) ||
                         (!g_realSavedGames.empty() && PathStartsWithI(realBase, g_realSavedGames));

    if (parts.size() <= 1) {
        candidate = parts[0];
    } else {
        size_t cutIndex = 1;

        
        if (IsGenericContainerFolder(parts[0]) && parts.size() >= 2) {
            cutIndex = 2;
        }

        std::wstring currentCheckPath = realBase;
        for (size_t i = 0; i < parts.size(); ++i) {
            currentCheckPath += L"\\" + parts[i];
            bool isLast = (i == parts.size() - 1);

            
            if (IsServiceDirectoryName(parts[i])) {
                cutIndex = max((size_t)1, i);
                break;
            }

            
            if (IsLikelyFileComponent(currentCheckPath, parts[i], isLast)) {
                cutIndex = max((size_t)1, i);
                break;
            }

            
            
            if (isDocsOrSaves && !IsGenericContainerFolder(parts[i])) {
                if (HasDirectFilesInDirectory(currentCheckPath)) {
                    cutIndex = i + 1;
                    break;
                }
            }

            
            if (i >= 6) {
                cutIndex = i + 1;
                break;
            }

            cutIndex = i + 1;
        }

        
        candidate = parts[0];
        for (size_t i = 1; i < cutIndex && i < parts.size(); ++i) {
            candidate += L"\\" + parts[i];
        }
    }

    std::wstring realTarget = realBase + L"\\" + candidate;
    std::wstring portTarget = portBase + L"\\" + candidate;

    if (IsPathNotEmpty(realTarget)) {
        return CheckAndHandleFolderMigration(realTarget, portTarget);
    }

    return ACTION_FRESH;
}

std::wstring RedirectPath(const std::wstring& originalPath, bool isWriteAccess = false) {
    if (originalPath.empty()) return originalPath;

    if (originalPath.rfind(L"\\\\.\\", 0) == 0 || originalPath.rfind(L"\\??\\", 0) == 0) {
        return originalPath;
    }

    if (originalPath.rfind(L"\\\\?\\", 0) == 0) {
        bool isDosDrive = (originalPath.length() >= 6 && iswalpha(originalPath[4]) && originalPath[5] == L':');
        bool isUncPath  = (originalPath.length() >= 8 && _wcsnicmp(originalPath.c_str(), L"\\\\?\\UNC\\", 8) == 0);
        if (!isDosDrive && !isUncPath) {
            return originalPath; 
        }
    }

    std::wstring workingPath = originalPath;
    bool hasLongPrefix = false;
    if (workingPath.rfind(L"\\\\?\\", 0) == 0) {
        hasLongPrefix = true;
        workingPath = workingPath.substr(4);
    }

    std::wstring clean = NormalizeSlashes(workingPath);
    wchar_t full[32768] = { 0 };
    DWORD fullLen = GetFullPathNameW(clean.c_str(), 32768, full, NULL);
    if (fullLen == 0) {
        LogFormat(LOG_LVL_FAIL, L"[VFS ERROR] GetFullPathNameW failed for: \"%s\" (Error: %lu)", originalPath.c_str(), GetLastError());
        return originalPath;
    }
    std::wstring path = full;

    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    if (PathStartsWithI(path, winDir)) return path;

    
    
    
    if (PathStartsWithI(path, g_appDir) && !PathStartsWithI(path, g_portableDir)) {
        if (g_enableUpdateFolder) {
            std::wstring updateDir = g_appDir + L"\\update";
            if (!PathStartsWithI(path, updateDir)) {
                std::wstring relApp = path.substr(g_appDir.length());
                while (!relApp.empty() && (relApp[0] == L'\\')) relApp.erase(0, 1);

                if (!relApp.empty()) {
                    std::wstring overloadCandidate = updateDir + L"\\" + relApp;
                    pfn_GetFileAttributesW pGetAttr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW : GetFileAttributesW;
                    if (pGetAttr(overloadCandidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        return overloadCandidate;
                    }
                }
            }
        }
        return path;
    }

    std::wstring sub;
    std::wstring targetBase;
    std::wstring realBase;

    
    auto MatchBaseFolder = [&](const std::wstring& checkPath, const std::wstring& longB, const std::wstring& shortB,
                               const std::wstring& targetB, std::wstring& outSub, std::wstring& outTargetBase, std::wstring& outRealBase) -> bool {
        if (!longB.empty() && PathStartsWithI(checkPath, longB)) {
            outSub = checkPath.substr(longB.length());
            outTargetBase = targetB;
            outRealBase = longB;
            return true;
        }
        if (!shortB.empty() && PathStartsWithI(checkPath, shortB)) {
            outSub = checkPath.substr(shortB.length());
            outTargetBase = targetB;
            outRealBase = longB; 
            return true;
        }
        return false;
    };

    if (PathStartsWithI(path, g_portableDir)) {
        std::wstring relPort = path.substr(g_portableDir.length());
        while (!relPort.empty() && (relPort[0] == L'\\')) relPort.erase(0, 1);

        if (PathStartsWithI(relPort, L"Temp")) {
            if (isWriteAccess) EnsureDirectoryTree(path, false);
            return path;
        }

        if (PathStartsWithI(relPort, L"AppData\\Roaming")) {
            sub = relPort.length() > 15 ? relPort.substr(15) : L"";
            targetBase = g_portableDir + L"\\AppData\\Roaming";
            realBase = g_realAppDataRoaming;
        } else if (PathStartsWithI(relPort, L"AppData\\LocalLow")) {
            sub = relPort.length() > 16 ? relPort.substr(16) : L"";
            targetBase = g_portableDir + L"\\AppData\\LocalLow";
            realBase = g_realAppDataLocalLow;
        } else if (PathStartsWithI(relPort, L"AppData\\Local")) {
            sub = relPort.length() > 13 ? relPort.substr(13) : L"";
            targetBase = g_portableDir + L"\\AppData\\Local";
            realBase = g_realAppDataLocal;
        } else if (PathStartsWithI(relPort, L"Documents\\Public")) {
            sub = relPort.length() > 16 ? relPort.substr(16) : L"";
            targetBase = g_portableDir + L"\\Documents\\Public";
            realBase = g_realPublicDocuments;
        } else if (PathStartsWithI(relPort, L"Documents")) {
            sub = relPort.length() > 9 ? relPort.substr(9) : L"";
            targetBase = g_portableDir + L"\\Documents";
            realBase = g_realDocuments;
        } else if (PathStartsWithI(relPort, L"Saved Games")) {
            sub = relPort.length() > 11 ? relPort.substr(11) : L"";
            targetBase = g_portableDir + L"\\Saved Games";
            realBase = g_realSavedGames;
        } else if (PathStartsWithI(relPort, L"ProgramData")) {
            sub = relPort.length() > 11 ? relPort.substr(11) : L"";
            targetBase = g_portableDir + L"\\ProgramData";
            realBase = g_realProgramData;
        } else if (PathStartsWithI(relPort, L"UserProfile")) {
            sub = relPort.length() > 11 ? relPort.substr(11) : L"";
            targetBase = g_portableDir + L"\\UserProfile";
            realBase = g_realUserProfile;
        } else {
            if (isWriteAccess) EnsureDirectoryTree(path, false);
            return path;
        }
    } else if (MatchBaseFolder(path, g_realAppDataRoaming, g_realAppDataRoamingShort, g_portableDir + L"\\AppData\\Roaming", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realAppDataLocalLow, g_realAppDataLocalLowShort, g_portableDir + L"\\AppData\\LocalLow", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realAppDataLocal, g_realAppDataLocalShort, g_portableDir + L"\\AppData\\Local", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realDocuments, g_realDocumentsShort, g_portableDir + L"\\Documents", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realSavedGames, g_realSavedGamesShort, g_portableDir + L"\\Saved Games", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realProgramData, g_realProgramDataShort, g_portableDir + L"\\ProgramData", sub, targetBase, realBase)) {
        
    } else if (MatchBaseFolder(path, g_realPublicDocuments, g_realPublicDocumentsShort, g_portableDir + L"\\Documents\\Public", sub, targetBase, realBase)) {
        
    }

    if (!targetBase.empty()) {
        std::wstring cleanSub = sub;
        while (!cleanSub.empty() && (cleanSub[0] == L'\\')) cleanSub.erase(0, 1);

        if (cleanSub.empty()) {
            if (isWriteAccess) EnsureDirectoryTree(targetBase, true);
            return targetBase;
        }

        
        if (StartsWithI(cleanSub, L"Temp")) {
            std::wstring tempSub = cleanSub.length() > 4 ? cleanSub.substr(4) : L"";
            while (!tempSub.empty() && (tempSub[0] == L'\\')) tempSub.erase(0, 1);
            std::wstring portTemp = g_portableDir + L"\\Temp" + (tempSub.empty() ? L"" : (L"\\" + tempSub));
            if (isWriteAccess) EnsureDirectoryTree(portTemp, false);
            return hasLongPrefix ? (L"\\\\?\\" + portTemp) : portTemp;
        }

        if (IsShaderCachePath(cleanSub)) {
            std::wstring redirected = targetBase + L"\\" + cleanSub;
            pfn_GetFileAttributesW pGetAttr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW : GetFileAttributesW;
            if (!isWriteAccess && pGetAttr(redirected.c_str()) == INVALID_FILE_ATTRIBUTES) {
                std::wstring realFile = realBase + L"\\" + cleanSub;
                if (pGetAttr(realFile.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    EnsureDirectoryTree(redirected, false);
                    if (Orig_CopyFileW) Orig_CopyFileW(realFile.c_str(), redirected.c_str(), TRUE);
                    else CopyFileW(realFile.c_str(), redirected.c_str(), TRUE);
                }
            }
            if (isWriteAccess) EnsureDirectoryTree(redirected, false);
            return redirected;
        }

        
        
        if (!IsOperationInitiatedByGame()) {
            return path;
        }

        
        if (g_processExiting.load(std::memory_order_relaxed)) {
            std::wstring redirected = targetBase + L"\\" + cleanSub;
            if (isWriteAccess) EnsureDirectoryTree(redirected, false);
            return redirected;
        }

        
        if (!isWriteAccess && cleanSub.length() >= 4) {
            std::wstring ext = ToUpper(cleanSub.substr(cleanSub.length() - 4));
            if (ext == L".DLL" || ext == L".SYS") {
                pfn_GetFileAttributesW pGetAttr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW : GetFileAttributesW;
                if (pGetAttr(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    return path;
                }
            }
        }

        std::wstring redirected = targetBase + L"\\" + cleanSub;
        pfn_GetFileAttributesW pGetAttr = Orig_GetFileAttributesW ? Orig_GetFileAttributesW : GetFileAttributesW;

        
        
        
        if (!isWriteAccess && (targetBase == g_portableDir + L"\\ProgramData")) {
            if (pGetAttr(redirected.c_str()) == INVALID_FILE_ATTRIBUTES) {
                std::wstring realFallback = realBase + L"\\" + cleanSub;
                if (pGetAttr(realFallback.c_str()) != INVALID_FILE_ATTRIBUTES) {
                    return realFallback;
                }
            }
        }

        MigrationAction act = InspectPathAndMigrate(cleanSub, realBase, targetBase);
        if (act == ACTION_PASSTHROUGH && !realBase.empty()) {
            return realBase + L"\\" + cleanSub;
        }

        if (isWriteAccess) EnsureDirectoryTree(redirected, false);
        return redirected;
    }

    return path;
}





static bool GetRedirectedFolder(int csidl, std::wstring& outPath) {
    int folder = csidl & 0xFF;
    if (folder == CSIDL_PERSONAL || folder == CSIDL_MYDOCUMENTS) {
        outPath = g_portableDir + L"\\Documents";
        return true;
    } else if (folder == CSIDL_COMMON_DOCUMENTS) {
        outPath = g_portableDir + L"\\Documents\\Public";
        return true;
    } else if (folder == CSIDL_APPDATA) {
        outPath = g_portableDir + L"\\AppData\\Roaming";
        return true;
    } else if (folder == CSIDL_LOCAL_APPDATA) {
        outPath = g_portableDir + L"\\AppData\\Local";
        return true;
    } else if (folder == CSIDL_COMMON_APPDATA) {
        outPath = g_portableDir + L"\\ProgramData";
        return true;
    }
    return false;
}

DWORD WINAPI Hook_GetTempPathW(DWORD nBufferLength, LPWSTR lpBuffer) {
    if (g_insideHook) return Orig_GetTempPathW(nBufferLength, lpBuffer);
    HookGuard guard;
    DWORD savedErr = GetLastError();

    std::wstring portTemp = g_portableDir + L"\\Temp\\";
    EnsureDirectoryTree(portTemp, true);

    DWORD len = (DWORD)portTemp.length();
    if (nBufferLength > len && lpBuffer) {
        wcscpy_s(lpBuffer, nBufferLength, portTemp.c_str());
        SetLastError(savedErr);
        return len;
    }
    SetLastError(savedErr);
    return len + 1;
}

DWORD WINAPI Hook_GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
    if (g_insideHook) return Orig_GetTempPathA(nBufferLength, lpBuffer);
    HookGuard guard;
    DWORD savedErr = GetLastError();

    wchar_t wBuf[MAX_PATH];
    DWORD wLen = Hook_GetTempPathW(MAX_PATH, wBuf);
    if (wLen == 0) return 0;

    int aLenNeeded = WideCharToMultiByte(CP_ACP, 0, wBuf, -1, NULL, 0, NULL, NULL);
    if (nBufferLength >= (DWORD)aLenNeeded && lpBuffer) {
        WideCharToMultiByte(CP_ACP, 0, wBuf, -1, lpBuffer, nBufferLength, NULL, NULL);
        SetLastError(savedErr);
        return (DWORD)(aLenNeeded - 1);
    }
    SetLastError(savedErr);
    return (DWORD)aLenNeeded;
}

HRESULT WINAPI Hook_SHGetKnownFolderPath(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken, PWSTR *ppszPath) {
    if (!ppszPath) return E_INVALIDARG;
    if (g_insideHook) return Orig_SHGetKnownFolderPath ? Orig_SHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath) : E_FAIL;
    HookGuard guard;

    std::wstring target;
    if (IsEqualGUID(rfid, FOLDERID_RoamingAppData)) target = g_portableDir + L"\\AppData\\Roaming";
    else if (IsEqualGUID(rfid, FOLDERID_LocalAppData)) target = g_portableDir + L"\\AppData\\Local";
    else if (IsEqualGUID(rfid, FOLDERID_LocalAppDataLow)) target = g_portableDir + L"\\AppData\\LocalLow";
    else if (IsEqualGUID(rfid, FOLDERID_Documents)) target = g_portableDir + L"\\Documents";
    else if (IsEqualGUID(rfid, FOLDERID_PublicDocuments)) target = g_portableDir + L"\\Documents\\Public";
    else if (IsEqualGUID(rfid, FOLDERID_SavedGames)) target = g_portableDir + L"\\Saved Games";
    else if (IsEqualGUID(rfid, FOLDERID_ProgramData)) target = g_portableDir + L"\\ProgramData";
    else if (IsEqualGUID(rfid, FOLDERID_Profile)) target = g_portableDir + L"\\UserProfile";

    if (!target.empty()) {
        EnsureDirectoryTree(target, true);
        size_t bytes = (target.length() + 1) * sizeof(wchar_t);
        *ppszPath = (PWSTR)CoTaskMemAlloc(bytes);
        if (*ppszPath) {
            wcscpy_s(*ppszPath, target.length() + 1, target.c_str());
            return S_OK;
        }
    }
    return Orig_SHGetKnownFolderPath ? Orig_SHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath) : E_FAIL;
}

HRESULT WINAPI Hook_SHGetFolderPathW(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPWSTR pszPath) {
    if (!pszPath) return E_INVALIDARG;
    if (g_insideHook) return Orig_SHGetFolderPathW ? Orig_SHGetFolderPathW(hwnd, csidl, hToken, dwFlags, pszPath) : E_FAIL;
    HookGuard guard;

    std::wstring target;
    if (GetRedirectedFolder(csidl, target)) {
        EnsureDirectoryTree(target, true);
        wcscpy_s(pszPath, MAX_PATH, target.c_str());
        return S_OK;
    }
    return Orig_SHGetFolderPathW ? Orig_SHGetFolderPathW(hwnd, csidl, hToken, dwFlags, pszPath) : E_FAIL;
}

HRESULT WINAPI Hook_SHGetFolderPathA(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPSTR pszPath) {
    if (!pszPath) return E_INVALIDARG;
    if (g_insideHook) return Orig_SHGetFolderPathA ? Orig_SHGetFolderPathA(hwnd, csidl, hToken, dwFlags, pszPath) : E_FAIL;
    HookGuard guard;

    std::wstring target;
    if (GetRedirectedFolder(csidl, target)) {
        EnsureDirectoryTree(target, true);
        WideCharToMultiByte(CP_ACP, 0, target.c_str(), -1, pszPath, MAX_PATH, NULL, NULL);
        return S_OK;
    }
    return Orig_SHGetFolderPathA ? Orig_SHGetFolderPathA(hwnd, csidl, hToken, dwFlags, pszPath) : E_FAIL;
}

BOOL WINAPI Hook_SHGetSpecialFolderPathW(HWND hwnd, LPWSTR pszPath, int csidl, BOOL fCreate) {
    if (!pszPath) return FALSE;
    if (g_insideHook) return Orig_SHGetSpecialFolderPathW ? Orig_SHGetSpecialFolderPathW(hwnd, pszPath, csidl, fCreate) : FALSE;
    HookGuard guard;

    std::wstring target;
    if (GetRedirectedFolder(csidl, target)) {
        EnsureDirectoryTree(target, true);
        wcscpy_s(pszPath, MAX_PATH, target.c_str());
        return TRUE;
    }
    return Orig_SHGetSpecialFolderPathW ? Orig_SHGetSpecialFolderPathW(hwnd, pszPath, csidl, fCreate) : FALSE;
}

BOOL WINAPI Hook_SHGetSpecialFolderPathA(HWND hwnd, LPSTR pszPath, int csidl, BOOL fCreate) {
    if (!pszPath) return FALSE;
    if (g_insideHook) return Orig_SHGetSpecialFolderPathA ? Orig_SHGetSpecialFolderPathA(hwnd, pszPath, csidl, fCreate) : FALSE;
    HookGuard guard;

    std::wstring target;
    if (GetRedirectedFolder(csidl, target)) {
        EnsureDirectoryTree(target, true);
        WideCharToMultiByte(CP_ACP, 0, target.c_str(), -1, pszPath, MAX_PATH, NULL, NULL);
        return TRUE;
    }
    return Orig_SHGetSpecialFolderPathA ? Orig_SHGetSpecialFolderPathA(hwnd, pszPath, csidl, fCreate) : FALSE;
}





void LoadPluginsFromDirectory(const std::wstring& directory) {
    std::wstring searchPattern = directory + L"\\*.asi";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = Orig_FindFirstFileW ? Orig_FindFirstFileW(searchPattern.c_str(), &fd) : FindFirstFileW(searchPattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    SetDllDirectoryW(directory.c_str());

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring pluginPath = directory + L"\\" + fd.cFileName;
            LogFormat(LOG_LVL_ALL, L"[ASI LOADER] Loading: \"%s\"", pluginPath.c_str());
            
            HMODULE hPlugin = LoadLibraryExW(pluginPath.c_str(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
            if (!hPlugin) {
                LogFormat(LOG_LVL_FAIL, L"[ASI FAILED] LoadLibraryExW: \"%s\" (Error: %lu)", pluginPath.c_str(), GetLastError());
            } else {
                typedef void (*pfn_InitializeASI)();
                pfn_InitializeASI pInit = (pfn_InitializeASI)GetProcAddress(hPlugin, "InitializeASI");
                if (pInit) {
                    pInit();
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    SetDllDirectoryW(g_appDir.c_str());
}

void LoadAllAsiPlugins() {
    if (!g_enablePlugins) return;
    
    
    LoadPluginsFromDirectory(g_appDir);
    
    
    std::wstring scriptsDir = g_appDir + L"\\scripts";
    DWORD attrScripts = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(scriptsDir.c_str()) : GetFileAttributesW(scriptsDir.c_str());
    if (attrScripts != INVALID_FILE_ATTRIBUTES && (attrScripts & FILE_ATTRIBUTE_DIRECTORY)) {
        LoadPluginsFromDirectory(scriptsDir);
    }

    
    std::wstring pluginsDir = g_appDir + L"\\plugins";
    DWORD attrPlugins = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(pluginsDir.c_str()) : GetFileAttributesW(pluginsDir.c_str());
    if (attrPlugins != INVALID_FILE_ATTRIBUTES && (attrPlugins & FILE_ATTRIBUTE_DIRECTORY)) {
        LoadPluginsFromDirectory(pluginsDir);
    }

    
    if (g_enableUpdateFolder) {
        std::wstring updateDir = g_appDir + L"\\update";
        DWORD attrUpdate = Orig_GetFileAttributesW ? Orig_GetFileAttributesW(updateDir.c_str()) : GetFileAttributesW(updateDir.c_str());
        if (attrUpdate != INVALID_FILE_ATTRIBUTES && (attrUpdate & FILE_ATTRIBUTE_DIRECTORY)) {
            LoadPluginsFromDirectory(updateDir);
        }
    }
}





static void*   g_pEntryPoint = NULL;
static uint8_t g_origOEPBytes[32] = { 0 };
static size_t  g_origOEPSize = 0;

extern "C" void OnEntryPointTriggered() {
	g_oepReached.store(true, std::memory_order_release);
    
    if (g_pEntryPoint && g_origOEPSize > 0) {
        DWORD oldProtect;
        if (VirtualProtect(g_pEntryPoint, g_origOEPSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memcpy(g_pEntryPoint, g_origOEPBytes, g_origOEPSize);
            VirtualProtect(g_pEntryPoint, g_origOEPSize, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), g_pEntryPoint, g_origOEPSize);
        }
    }

    
    LoadAllAsiPlugins();
}

#if defined(_M_IX86) || defined(__i386__)
__declspec(naked) void Hook_EntryPoint_x86() {
    __asm {
        pushad
        pushfd
        cld
    }

    OnEntryPointTriggered();

    __asm {
        popfd
        popad
        jmp dword ptr [g_pEntryPoint]
    }
}
#endif

void InstallEntryPointHook() {
    HMODULE hExe = GetModuleHandleW(NULL);
    if (!hExe) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] GetModuleHandleW failed (Error: %lu)", GetLastError());
        return;
    }

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hExe;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] Invalid DOS signature: 0x%04X", pDos->e_magic);
        return;
    }

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((uint8_t*)hExe + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] Invalid NT signature: 0x%08X", pNt->Signature);
        return;
    }

    void* pEntryPoint = (void*)((uint8_t*)hExe + pNt->OptionalHeader.AddressOfEntryPoint);
    if (!pEntryPoint) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] AddressOfEntryPoint is NULL");
        return;
    }

    g_pEntryPoint = pEntryPoint;

    size_t stolenBytes = 0;
    while (stolenBytes < 5 && stolenBytes < sizeof(g_origOEPBytes)) {
#if defined(_M_X64) || defined(__x86_64__)
        size_t len = GetInstructionLength((const uint8_t*)pEntryPoint + stolenBytes, true);
#else
        size_t len = GetInstructionLength((const uint8_t*)pEntryPoint + stolenBytes, false);
#endif
        if (len == 0) len = 1;
        stolenBytes += len;
    }

    if (stolenBytes < 5 || stolenBytes > sizeof(g_origOEPBytes)) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] Invalid stolen bytes count: %zu", stolenBytes);
        return;
    }
    g_origOEPSize = stolenBytes;

#if defined(_M_X64) || defined(__x86_64__)
    uint8_t* pStub = (uint8_t*)AllocateTrampolineBufferNear(pEntryPoint, 128);
    if (!pStub) {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] Failed to allocate trampoline buffer near OEP");
        return;
    }

    std::vector<uint8_t> code;
    
    code.insert(code.end(), { 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57 }); 
    code.insert(code.end(), { 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 }); 
    code.push_back(0x9C); 

    
    code.insert(code.end(), { 0x48, 0x89, 0xE3 });       
    code.insert(code.end(), { 0x48, 0x83, 0xEC, 0x20 }); 
    code.insert(code.end(), { 0x48, 0x83, 0xE4, 0xF0 }); 

    
    code.insert(code.end(), { 0x48, 0xB8 });
    uint64_t fnTrigger = (uint64_t)OnEntryPointTriggered;
    code.insert(code.end(), (uint8_t*)&fnTrigger, (uint8_t*)&fnTrigger + 8);
    code.insert(code.end(), { 0xFF, 0xD0 });             

    
    code.insert(code.end(), { 0x48, 0x89, 0xDC });       
    code.push_back(0x9D);                                
    code.insert(code.end(), { 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58 }); 
    code.insert(code.end(), { 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58 }); 

    
    code.insert(code.end(), { 0x49, 0xBB });
    uint64_t targetOEP = (uint64_t)pEntryPoint;
    code.insert(code.end(), (uint8_t*)&targetOEP, (uint8_t*)&targetOEP + 8);
    code.insert(code.end(), { 0x41, 0xFF, 0xE3 });       

    memcpy(pStub, code.data(), code.size());
    FlushInstructionCache(GetCurrentProcess(), pStub, code.size());

    void* hookDestination = pStub;
#else
    void* hookDestination = (void*)Hook_EntryPoint_x86;
#endif

    SuspendOtherThreadsSafe();

    DWORD oldProtect;
    if (VirtualProtect(pEntryPoint, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(g_origOEPBytes, pEntryPoint, stolenBytes);
        
        uint8_t* pTarget = (uint8_t*)pEntryPoint;
        pTarget[0] = 0xE9;
        *(int32_t*)&pTarget[1] = (int32_t)((uint8_t*)hookDestination - (pTarget + 5));
        for (size_t i = 5; i < stolenBytes; i++) pTarget[i] = 0x90;

        VirtualProtect(pEntryPoint, stolenBytes, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), pEntryPoint, stolenBytes);
    } else {
        LogFormat(LOG_LVL_FAIL, L"[OEP HOOK ERROR] VirtualProtect failed on entry point (Error: %lu)", GetLastError());
    }

    ResumeOtherThreadsSafe();
}





HANDLE WINAPI Hook_CreateFileW(LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSec, DWORD dwDisp, DWORD dwFlags, HANDLE hTemplate) {
    if (!Orig_CreateFileW) return INVALID_HANDLE_VALUE;
    if (!lpFileName) return Orig_CreateFileW(lpFileName, dwAccess, dwShare, lpSec, dwDisp, dwFlags, hTemplate);
    if (g_insideHook) return Orig_CreateFileW(lpFileName, dwAccess, dwShare, lpSec, dwDisp, dwFlags, hTemplate);
    HookGuard guard;

    bool isWrite = (dwAccess & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA)) != 0;
    
    std::wstring finalPath = RedirectPath(lpFileName, isWrite);
    HANDLE h = Orig_CreateFileW(finalPath.c_str(), dwAccess, dwShare, lpSec, dwDisp, dwFlags, hTemplate);
    DWORD err = GetLastError();

    
    
    if (!g_processExiting.load(std::memory_order_relaxed)) {
        bool isDevicePath = (lpFileName[0] == L'\\' && lpFileName[1] == L'\\');
        if (h == INVALID_HANDLE_VALUE) {
            if (!isDevicePath) {
                LogFormat(LOG_LVL_FAIL, L"[FILE FAILED] CreateFileW: \"%s\" -> \"%s\" (Access: 0x%08X, Disp: %u, Error: %lu)", 
                    lpFileName, finalPath.c_str(), dwAccess, dwDisp, err);
            }
        } else {
            if (!isDevicePath) {
                LogFormat(LOG_LVL_ALL, L"[FILE OK] CreateFileW: \"%s\" -> \"%s\" (Access: 0x%08X)", 
                    lpFileName, finalPath.c_str(), dwAccess);
            }
        }
    }

    SetLastError(err);
    return h;
}

HANDLE WINAPI Hook_CreateFileA(LPCSTR lpFileName, DWORD dwAccess, DWORD dwShare,
    LPSECURITY_ATTRIBUTES lpSec, DWORD dwDisp, DWORD dwFlags, HANDLE hTemplate) {
    if (!lpFileName) return INVALID_HANDLE_VALUE;
    if (g_insideHook) return Orig_CreateFileA ? Orig_CreateFileA(lpFileName, dwAccess, dwShare, lpSec, dwDisp, dwFlags, hTemplate) : INVALID_HANDLE_VALUE;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wPath, MAX_PATH * 2);
    return Hook_CreateFileW(wPath, dwAccess, dwShare, lpSec, dwDisp, dwFlags, hTemplate);
}

DWORD WINAPI Hook_GetFileAttributesW(LPCWSTR lpFileName) {
    if (!Orig_GetFileAttributesW) return INVALID_FILE_ATTRIBUTES;
    if (g_insideHook || !lpFileName) return Orig_GetFileAttributesW(lpFileName);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpFileName, false);
    DWORD res = Orig_GetFileAttributesW(finalPath.c_str());
    DWORD err = GetLastError();

    if (res == INVALID_FILE_ATTRIBUTES) {
        LogFormat(LOG_LVL_FAIL, L"[FILE NOT FOUND] GetFileAttributesW: \"%s\" -> \"%s\" (Error: %lu)", 
            lpFileName, finalPath.c_str(), err);
    } else {
        LogFormat(LOG_LVL_ALL, L"[FILE OK] GetFileAttributesW: \"%s\" -> \"%s\" (Attr: 0x%08X)", 
            lpFileName, finalPath.c_str(), res);
    }

    SetLastError(err);
    return res;
}

DWORD WINAPI Hook_GetFileAttributesA(LPCSTR lpFileName) {
    if (!lpFileName) return INVALID_FILE_ATTRIBUTES;
    if (g_insideHook) return Orig_GetFileAttributesA ? Orig_GetFileAttributesA(lpFileName) : INVALID_FILE_ATTRIBUTES;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wPath, MAX_PATH * 2);
    return Hook_GetFileAttributesW(wPath);
}

BOOL WINAPI Hook_GetFileAttributesExW(LPCWSTR lpFileName, GET_FILEEX_INFO_LEVELS fInfoLevelId, LPVOID lpFileInformation) {
    if (!Orig_GetFileAttributesExW) return FALSE;
    if (g_insideHook || !lpFileName) return Orig_GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpFileName, false);
    BOOL res = Orig_GetFileAttributesExW(finalPath.c_str(), fInfoLevelId, lpFileInformation);
    DWORD err = GetLastError();

    if (!res) {
        LogFormat(LOG_LVL_FAIL, L"[FILE NOT FOUND] GetFileAttributesExW: \"%s\" -> \"%s\" (Error: %lu)", 
            lpFileName, finalPath.c_str(), err);
    } else {
        LogFormat(LOG_LVL_ALL, L"[FILE OK] GetFileAttributesExW: \"%s\" -> \"%s\"", 
            lpFileName, finalPath.c_str());
    }

    SetLastError(err);
    return res;
}

HANDLE WINAPI Hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    if (!Orig_FindFirstFileW) return INVALID_HANDLE_VALUE;
    if (g_insideHook || !lpFileName) return Orig_FindFirstFileW(lpFileName, lpFindFileData);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpFileName, false);
    HANDLE h = Orig_FindFirstFileW(finalPath.c_str(), lpFindFileData);
    DWORD err = GetLastError();

    if (h == INVALID_HANDLE_VALUE) {
        LogFormat(LOG_LVL_FAIL, L"[FIND NOT FOUND] FindFirstFileW: \"%s\" -> \"%s\" (Error: %lu)", 
            lpFileName, finalPath.c_str(), err);
    } else {
        LogFormat(LOG_LVL_ALL, L"[FIND OK] FindFirstFileW: \"%s\" -> \"%s\"", 
            lpFileName, finalPath.c_str());
    }

    SetLastError(err);
    return h;
}

HANDLE WINAPI Hook_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    if (!lpFileName) return INVALID_HANDLE_VALUE;
    if (g_insideHook) return Orig_FindFirstFileA ? Orig_FindFirstFileA(lpFileName, lpFindFileData) : INVALID_HANDLE_VALUE;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wPath, MAX_PATH * 2);
    WIN32_FIND_DATAW fdW;
    HANDLE h = Hook_FindFirstFileW(wPath, &fdW);
    DWORD err = GetLastError();
    if (h != INVALID_HANDLE_VALUE && lpFindFileData) {
        lpFindFileData->dwFileAttributes = fdW.dwFileAttributes;
        lpFindFileData->ftCreationTime = fdW.ftCreationTime;
        lpFindFileData->ftLastAccessTime = fdW.ftLastAccessTime;
        lpFindFileData->ftLastWriteTime = fdW.ftLastWriteTime;
        lpFindFileData->nFileSizeHigh = fdW.nFileSizeHigh;
        lpFindFileData->nFileSizeLow = fdW.nFileSizeLow;
        WideCharToMultiByte(CP_ACP, 0, fdW.cFileName, -1, lpFindFileData->cFileName, MAX_PATH, NULL, NULL);
        WideCharToMultiByte(CP_ACP, 0, fdW.cAlternateFileName, -1, lpFindFileData->cAlternateFileName, 14, NULL, NULL);
    }
    SetLastError(err);
    return h;
}

HANDLE WINAPI Hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
    FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
    if (!Orig_FindFirstFileExW) return INVALID_HANDLE_VALUE;
    if (g_insideHook || !lpFileName) return Orig_FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpFileName, false);
    HANDLE h = Orig_FindFirstFileExW(finalPath.c_str(), fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    DWORD err = GetLastError();

    if (h == INVALID_HANDLE_VALUE) {
        LogFormat(LOG_LVL_FAIL, L"[FIND NOT FOUND] FindFirstFileExW: \"%s\" -> \"%s\" (Error: %lu)", 
            lpFileName, finalPath.c_str(), err);
    } else {
        LogFormat(LOG_LVL_ALL, L"[FIND OK] FindFirstFileExW: \"%s\" -> \"%s\"", 
            lpFileName, finalPath.c_str());
    }

    SetLastError(err);
    return h;
}

BOOL WINAPI Hook_CreateDirectoryW(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSec) {
    if (!Orig_CreateDirectoryW) return FALSE;
    if (g_insideHook || !lpPathName) return Orig_CreateDirectoryW(lpPathName, lpSec);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpPathName, true);
    EnsureDirectoryTree(finalPath, true);
    BOOL res = Orig_CreateDirectoryW(finalPath.c_str(), lpSec);
    DWORD err = GetLastError();

    if (!res) {
        if (err != ERROR_ALREADY_EXISTS) {
            LogFormat(LOG_LVL_FAIL, L"[DIR CREATE FAILED] CreateDirectoryW: \"%s\" -> \"%s\" (Error: %lu)", 
                lpPathName, finalPath.c_str(), err);
        }
    } else {
        LogFormat(LOG_LVL_ALL, L"[DIR CREATED] CreateDirectoryW: \"%s\" -> \"%s\"", 
            lpPathName, finalPath.c_str());
    }

    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSec) {
    if (!lpPathName) return FALSE;
    if (g_insideHook) return Orig_CreateDirectoryA ? Orig_CreateDirectoryA(lpPathName, lpSec) : FALSE;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpPathName, -1, wPath, MAX_PATH * 2);
    return Hook_CreateDirectoryW(wPath, lpSec);
}

BOOL WINAPI Hook_DeleteFileW(LPCWSTR lpFileName) {
    if (!Orig_DeleteFileW) return FALSE;
    if (!lpFileName || lpFileName[0] == L'\0') {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return FALSE;
    }
    if (g_insideHook) return Orig_DeleteFileW(lpFileName);
    HookGuard guard;

    
    std::wstring finalPath = RedirectPath(lpFileName, true);
    BOOL res = Orig_DeleteFileW(finalPath.c_str());
    DWORD err = GetLastError();

    if (!g_processExiting.load(std::memory_order_relaxed)) {
        if (!res) {
            LogFormat(LOG_LVL_FAIL, L"[FILE DELETE FAILED] DeleteFileW: \"%s\" -> \"%s\" (Error: %lu)", 
                lpFileName, finalPath.c_str(), err);
        } else {
            LogFormat(LOG_LVL_ALL, L"[FILE DELETED] DeleteFileW: \"%s\" -> \"%s\"", 
                lpFileName, finalPath.c_str());
        }
    }

    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_DeleteFileA(LPCSTR lpFileName) {
    if (!lpFileName) return FALSE;
    if (g_insideHook) return Orig_DeleteFileA ? Orig_DeleteFileA(lpFileName) : FALSE;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wPath, MAX_PATH * 2);
    return Hook_DeleteFileW(wPath);
}

BOOL WINAPI Hook_RemoveDirectoryW(LPCWSTR lpPathName) {
    if (!Orig_RemoveDirectoryW) return FALSE;
    if (g_insideHook || !lpPathName) return Orig_RemoveDirectoryW(lpPathName);
    HookGuard guard;
    std::wstring finalPath = RedirectPath(lpPathName, true);
    BOOL res = Orig_RemoveDirectoryW(finalPath.c_str());
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_RemoveDirectoryA(LPCSTR lpPathName) {
    if (!lpPathName) return FALSE;
    if (g_insideHook) return Orig_RemoveDirectoryA ? Orig_RemoveDirectoryA(lpPathName) : FALSE;
    wchar_t wPath[MAX_PATH * 2] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpPathName, -1, wPath, MAX_PATH * 2);
    return Hook_RemoveDirectoryW(wPath);
}

BOOL WINAPI Hook_MoveFileW(LPCWSTR lpExisting, LPCWSTR lpNew) {
    if (!Orig_MoveFileW) return FALSE;
    if (g_insideHook) return Orig_MoveFileW(lpExisting, lpNew);
    HookGuard guard;
    std::wstring from = RedirectPath(lpExisting ? lpExisting : L"", false);
    std::wstring to = RedirectPath(lpNew ? lpNew : L"", true);
    EnsureDirectoryTree(to, false);
    BOOL res = Orig_MoveFileW(from.c_str(), to.c_str());
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_MoveFileExW(LPCWSTR lpExisting, LPCWSTR lpNew, DWORD dwFlags) {
    if (!Orig_MoveFileExW) return FALSE;
    if (g_insideHook) return Orig_MoveFileExW(lpExisting, lpNew, dwFlags);
    HookGuard guard;
    std::wstring from = RedirectPath(lpExisting ? lpExisting : L"", false);
    std::wstring to = RedirectPath(lpNew ? lpNew : L"", true);
    EnsureDirectoryTree(to, false);
    BOOL res = Orig_MoveFileExW(from.c_str(), to.c_str(), dwFlags);
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_CopyFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailIfExists) {
    if (!Orig_CopyFileW) return FALSE;
    if (g_insideHook) return Orig_CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
    HookGuard guard;
    std::wstring from = RedirectPath(lpExistingFileName ? lpExistingFileName : L"", false);
    std::wstring to = RedirectPath(lpNewFileName ? lpNewFileName : L"", true);
    EnsureDirectoryTree(to, false);
    BOOL res = Orig_CopyFileW(from.c_str(), to.c_str(), bFailIfExists);
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_CopyFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData, LPBOOL pbCancel, DWORD dwCopyFlags) {
    if (!Orig_CopyFileExW) return FALSE;
    if (g_insideHook) return Orig_CopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    HookGuard guard;
    std::wstring from = RedirectPath(lpExistingFileName ? lpExistingFileName : L"", false);
    std::wstring to = RedirectPath(lpNewFileName ? lpNewFileName : L"", true);
    EnsureDirectoryTree(to, false);
    BOOL res = Orig_CopyFileExW(from.c_str(), to.c_str(), lpProgressRoutine, lpData, pbCancel, dwCopyFlags);
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_ReplaceFileW(LPCWSTR lpReplacedFileName, LPCWSTR lpReplacementFileName,
    LPCWSTR lpBackupFileName, DWORD dwReplaceFlags, LPVOID lpExclude, LPVOID lpReserved) {
    if (!Orig_ReplaceFileW) return FALSE;
    if (g_insideHook) return Orig_ReplaceFileW(lpReplacedFileName, lpReplacementFileName, lpBackupFileName, dwReplaceFlags, lpExclude, lpReserved);
    HookGuard guard;
    std::wstring replaced = RedirectPath(lpReplacedFileName ? lpReplacedFileName : L"", true);
    std::wstring replacement = RedirectPath(lpReplacementFileName ? lpReplacementFileName : L"", false);
    std::wstring backup = lpBackupFileName ? RedirectPath(lpBackupFileName, true) : L"";
    
    BOOL res = Orig_ReplaceFileW(replaced.c_str(), replacement.c_str(), 
        backup.empty() ? NULL : backup.c_str(), dwReplaceFlags, lpExclude, lpReserved);
    DWORD err = GetLastError();
    SetLastError(err);
    return res;
}

BOOL WINAPI Hook_ReplaceFileA(LPCSTR lpReplacedFileName, LPCSTR lpReplacementFileName,
    LPCSTR lpBackupFileName, DWORD dwReplaceFlags, LPVOID lpExclude, LPVOID lpReserved) {
    if (!Orig_ReplaceFileA && !Orig_ReplaceFileW) return FALSE;
    if (g_insideHook) return Orig_ReplaceFileA ? Orig_ReplaceFileA(lpReplacedFileName, lpReplacementFileName, lpBackupFileName, dwReplaceFlags, lpExclude, lpReserved) : FALSE;
    wchar_t wReplaced[MAX_PATH * 2] = { 0 };
    wchar_t wReplacement[MAX_PATH * 2] = { 0 };
    wchar_t wBackup[MAX_PATH * 2] = { 0 };
    if (lpReplacedFileName) MultiByteToWideChar(CP_ACP, 0, lpReplacedFileName, -1, wReplaced, MAX_PATH * 2);
    if (lpReplacementFileName) MultiByteToWideChar(CP_ACP, 0, lpReplacementFileName, -1, wReplacement, MAX_PATH * 2);
    if (lpBackupFileName) MultiByteToWideChar(CP_ACP, 0, lpBackupFileName, -1, wBackup, MAX_PATH * 2);

    return Hook_ReplaceFileW(
        lpReplacedFileName ? wReplaced : NULL,
        lpReplacementFileName ? wReplacement : NULL,
        lpBackupFileName ? wBackup : NULL,
        dwReplaceFlags, lpExclude, lpReserved
    );
}





bool CheckRealRegKeyExists(const std::wstring& fullKey) {
    HKEY hRoot = NULL;
    std::wstring subKey;
    if (StartsWithI(fullKey, L"HKCU\\")) {
        hRoot = HKEY_CURRENT_USER;
        subKey = fullKey.substr(5);
    } else if (StartsWithI(fullKey, L"HKLM\\")) {
        hRoot = HKEY_LOCAL_MACHINE;
        subKey = fullKey.substr(5);
    } else {
        return false;
    }

    HKEY hTest = NULL;
    pfn_RegOpenKeyExW pOpen = Orig_RegOpenKeyExW ? Orig_RegOpenKeyExW : RegOpenKeyExW;
    pfn_RegCloseKey pClose = Orig_RegCloseKey ? Orig_RegCloseKey : RegCloseKey;
    
    if (pOpen(hRoot, subKey.c_str(), 0, KEY_READ, &hTest) == ERROR_SUCCESS) {
        pClose(hTest);
        return true;
    }
    return false;
}

LSTATUS WINAPI Hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    if (!phkResult) return ERROR_INVALID_PARAMETER;
    if (!Orig_RegOpenKeyExW) return ERROR_INVALID_HANDLE;

    if (g_insideHook && !IS_FAKE_HKEY(hKey)) {
        return Orig_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    HookGuard guard;

    std::wstring base = RootKeyToString(hKey);
    std::wstring sub = lpSubKey ? lpSubKey : L"";
    std::wstring full = NormalizeRegKey(sub.empty() ? base : (base + L"\\" + sub));

    LSTATUS status = ERROR_SUCCESS;

    
    if (IsCallerSteamFix(_ReturnAddress()) || !ShouldVirtualizeKey(full)) {
        status = Orig_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        if (status == ERROR_SUCCESS && phkResult && *phkResult) {
            std::lock_guard<std::recursive_mutex> lock(g_regMutex);
            g_trackedRealHandles[*phkResult] = full;
        }
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] Open REAL Key: \"%s\" (sam: 0x%08X) -> Status: %lu", full.c_str(), samDesired, status);
        return status;
    }

    
    if (IsKeyInVirtualReg(full)) {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        HKEY fake = (HKEY)(uintptr_t)(++g_nextHandleId);
        g_openHandles[fake] = { full };
        *phkResult = fake;
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] Open FAKE Key: \"%s\" -> SUCCESS", full.c_str());
        return ERROR_SUCCESS;
    }

    
    if (CheckRealRegKeyExists(full)) {
        status = Orig_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        if (status == ERROR_SUCCESS && phkResult && *phkResult) {
            std::lock_guard<std::recursive_mutex> lock(g_regMutex);
            g_trackedRealHandles[*phkResult] = full;
        }
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] Open REAL Fallback: \"%s\" -> Status: %lu", full.c_str(), status);
        return status;
    }

    LogFormat(LOG_LVL_ALL, L"[REG TRACE] Open FAILED: \"%s\" -> ERROR_FILE_NOT_FOUND", full.c_str());
    return ERROR_FILE_NOT_FOUND;
}


LSTATUS WINAPI Hook_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSec, PHKEY phkResult, LPDWORD lpdwDisp) {
    if (!phkResult) return ERROR_INVALID_PARAMETER;
    if (!Orig_RegCreateKeyExW) return ERROR_INVALID_HANDLE;

    if (g_insideHook) {
        return Orig_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSec, phkResult, lpdwDisp);
    }
    HookGuard guard;

    std::wstring base = RootKeyToString(hKey);
    std::wstring sub = lpSubKey ? lpSubKey : L"";
    std::wstring full = NormalizeRegKey(sub.empty() ? base : (base + L"\\" + sub));

    LSTATUS status = ERROR_SUCCESS;

    
    if (IsCallerSteamFix(_ReturnAddress()) || !ShouldVirtualizeKey(full)) {
        status = Orig_RegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSec, phkResult, lpdwDisp);
        if (status == ERROR_SUCCESS && phkResult && *phkResult) {
            std::lock_guard<std::recursive_mutex> lock(g_regMutex);
            g_trackedRealHandles[*phkResult] = full;
        }
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] Create REAL Key: \"%s\" (sam: 0x%08X) -> Status: %lu", full.c_str(), samDesired, status);
        return status;
    }

    
    bool exists = false;
    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        exists = (g_vRegData.find(full) != g_vRegData.end());
        g_vRegData[full];

        HKEY fake = (HKEY)(uintptr_t)(++g_nextHandleId);
        g_openHandles[fake] = { full };
        *phkResult = fake;
        if (lpdwDisp) *lpdwDisp = exists ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
    }

    LogFormat(LOG_LVL_ALL, L"[REG TRACE] Create FAKE Key: \"%s\" -> SUCCESS (New: %d)", full.c_str(), exists ? 0 : 1);
    SaveRegistryToIni();
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult) {
    if (!phkResult) return ERROR_INVALID_PARAMETER;
    if (g_insideHook) return Orig_RegOpenKeyExA ? Orig_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult) : ERROR_INVALID_HANDLE;

    
    if (IsCallerSteamFix(_ReturnAddress()) || !IS_FAKE_HKEY(hKey)) {
        std::wstring base = RootKeyToString(hKey);
        std::string sub = lpSubKey ? lpSubKey : "";
        std::wstring full = NormalizeRegKey(base + (sub.empty() ? L"" : (L"\\" + Utf8ToWide(sub))));

        if (!ShouldVirtualizeKey(full)) {
            LSTATUS st = Orig_RegOpenKeyExA ? Orig_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult) : ERROR_INVALID_HANDLE;
            if (st == ERROR_SUCCESS && phkResult && *phkResult) {
                std::lock_guard<std::recursive_mutex> lock(g_regMutex);
                g_trackedRealHandles[*phkResult] = full;
            }
            return st;
        }
    }

    wchar_t wSub[1024] = { 0 };
    if (lpSubKey) MultiByteToWideChar(CP_ACP, 0, lpSubKey, -1, wSub, 1024);
    return Hook_RegOpenKeyExW(hKey, lpSubKey ? wSub : NULL, ulOptions, samDesired, phkResult);
}

LSTATUS WINAPI Hook_RegOpenKeyW(HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult) {
    return Hook_RegOpenKeyExW(hKey, lpSubKey, 0, MAXIMUM_ALLOWED, phkResult);
}

LSTATUS WINAPI Hook_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult) {
    return Hook_RegOpenKeyExA(hKey, lpSubKey, 0, MAXIMUM_ALLOWED, phkResult);
}



LSTATUS WINAPI Hook_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSec, PHKEY phkResult, LPDWORD lpdwDisp) {
    if (g_insideHook) return Orig_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSec, phkResult, lpdwDisp);
    wchar_t wSub[1024] = { 0 };
    if (lpSubKey) MultiByteToWideChar(CP_ACP, 0, lpSubKey, -1, wSub, 1024);
    return Hook_RegCreateKeyExW(hKey, lpSubKey ? wSub : NULL, Reserved, NULL, dwOptions, samDesired, lpSec, phkResult, lpdwDisp);
}

LSTATUS WINAPI Hook_RegCloseKey(HKEY hKey) {
    if (!hKey) return ERROR_INVALID_HANDLE;

    if (g_processExiting.load(std::memory_order_relaxed)) {
        if (IS_FAKE_HKEY(hKey)) return ERROR_SUCCESS;
        return Orig_RegCloseKey ? Orig_RegCloseKey(hKey) : RegCloseKey(hKey);
    }

    if (IS_FAKE_HKEY(hKey)) {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        g_openHandles.erase(hKey);
        return ERROR_SUCCESS;
    }

    if (g_insideHook) return Orig_RegCloseKey ? Orig_RegCloseKey(hKey) : ERROR_SUCCESS;
    HookGuard guard;

    if (IS_FAKE_HKEY(hKey)) {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        g_openHandles.erase(hKey);
        return ERROR_SUCCESS;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        if (!g_trackedRealHandles.empty()) {
            g_trackedRealHandles.erase(hKey);
        }
    }

    return Orig_RegCloseKey ? Orig_RegCloseKey(hKey) : RegCloseKey(hKey);
}



LSTATUS WINAPI Hook_RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    if (!Orig_RegQueryValueExW) return ERROR_INVALID_HANDLE;
    if (g_insideHook) return Orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) {
        return Orig_RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    }

    std::wstring valName = lpValueName ? lpValueName : L"";
    std::lock_guard<std::recursive_mutex> lock(g_regMutex);

    auto hIt = g_openHandles.find(hKey);
    if (hIt == g_openHandles.end()) return ERROR_INVALID_HANDLE;

    auto kIt = g_vRegData.find(hIt->second.subKey);
    if (kIt != g_vRegData.end()) {
        auto vIt = kIt->second.find(valName);
        if (vIt != kIt->second.end()) {
            if (lpType) *lpType = vIt->second.type;
            DWORD size = (DWORD)vIt->second.data.size();

            if (!lpData) {
                if (lpcbData) *lpcbData = size;
                LogFormat(LOG_LVL_ALL, L"[REG QUERY SIZE] RegQueryValueExW (Virtual): [%s] \"%s\" = %lu bytes", hIt->second.subKey.c_str(), valName.c_str(), size);
                return ERROR_SUCCESS;
            }
            if (!lpcbData) return ERROR_INVALID_PARAMETER;

            if (*lpcbData < size) {
                *lpcbData = size;
                return ERROR_MORE_DATA;
            }
            *lpcbData = size;
            if (size > 0) memcpy(lpData, vIt->second.data.data(), size);
            LogFormat(LOG_LVL_ALL, L"[REG QUERY OK] RegQueryValueExW (Virtual): [%s] \"%s\" (Type: %u, Size: %lu)", hIt->second.subKey.c_str(), valName.c_str(), vIt->second.type, size);
            return ERROR_SUCCESS;
        }
    }

    LogFormat(LOG_LVL_FAIL, L"[REG VALUE NOT FOUND] RegQueryValueExW (Virtual): [%s] \"%s\"", hIt->second.subKey.c_str(), valName.c_str());
    return ERROR_FILE_NOT_FOUND;
}

LSTATUS WINAPI Hook_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    if (g_insideHook) return Orig_RegSetValueExW ? Orig_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData) : ERROR_INVALID_HANDLE;
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) {
        LSTATUS st = Orig_RegSetValueExW ? Orig_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData) : ERROR_INVALID_HANDLE;
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] SetValueW (REAL hKey=%p): \"%s\" -> Status: %lu", hKey, lpValueName ? lpValueName : L"", st);
        return st;
    }

    std::wstring valName = lpValueName ? lpValueName : L"";
    std::wstring keyPath;
    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        auto it = g_openHandles.find(hKey);
        if (it != g_openHandles.end()) {
            keyPath = it->second.subKey;
            RegValEntry entry;
            entry.type = dwType;
            if (lpData && cbData > 0) {
                entry.data.assign(lpData, lpData + cbData);
            }
            g_vRegData[keyPath][valName] = entry;
        } else {
            LogFormat(LOG_LVL_ALL, L"[REG TRACE] SetValueW FAILED: Invalid Fake Handle %p", hKey);
            return ERROR_INVALID_HANDLE;
        }
    }

    LogFormat(LOG_LVL_ALL, L"[REG TRACE] SetValueW (FAKE): [%s] \"%s\" -> SUCCESS", keyPath.c_str(), valName.c_str());
    SaveRegistryToIni();
    return ERROR_SUCCESS;
}


LSTATUS WINAPI Hook_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    if (g_insideHook) return Orig_RegSetValueExA ? Orig_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData) : ERROR_INVALID_HANDLE;

    
    if (!IS_FAKE_HKEY(hKey)) {
        LSTATUS st = Orig_RegSetValueExA ? Orig_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData) : ERROR_INVALID_HANDLE;
        LogFormat(LOG_LVL_ALL, L"[REG TRACE] SetValueA (REAL hKey=%p): \"%S\" -> Status: %lu", hKey, lpValueName ? lpValueName : "", st);
        return st;
    }

    
    wchar_t wName[512] = { 0 };
    if (lpValueName) MultiByteToWideChar(CP_ACP, 0, lpValueName, -1, wName, 512);

    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
        int wLen = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpData, cbData, NULL, 0);
        std::vector<wchar_t> wData(max(1, wLen));
        if (wLen > 0) MultiByteToWideChar(CP_ACP, 0, (LPCSTR)lpData, cbData, wData.data(), wLen);
        return Hook_RegSetValueExW(hKey, lpValueName ? wName : NULL, Reserved, dwType, (BYTE*)wData.data(), (DWORD)(wLen * sizeof(wchar_t)));
    }
    return Hook_RegSetValueExW(hKey, lpValueName ? wName : NULL, Reserved, dwType, lpData, cbData);
}


LSTATUS WINAPI Hook_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    if (!Orig_RegQueryValueExA) return ERROR_INVALID_HANDLE;
    if (g_insideHook) return Orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    if (!IS_FAKE_HKEY(hKey)) return Orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

    wchar_t wName[512] = { 0 };
    if (lpValueName) MultiByteToWideChar(CP_ACP, 0, lpValueName, -1, wName, 512);

    DWORD dwType = 0, cbData = 0;
    LSTATUS st = Hook_RegQueryValueExW(hKey, lpValueName ? wName : NULL, lpReserved, &dwType, NULL, &cbData);
    if (st != ERROR_SUCCESS) return st;

    if (lpType) *lpType = dwType;

    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
        std::vector<BYTE> buf(cbData + sizeof(wchar_t), 0);
        st = Hook_RegQueryValueExW(hKey, lpValueName ? wName : NULL, lpReserved, &dwType, buf.data(), &cbData);
        if (st != ERROR_SUCCESS) return st;

        int aLen = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)buf.data(), -1, NULL, 0, NULL, NULL);
        if (aLen <= 0) aLen = 1;

        if (!lpData) {
            if (lpcbData) *lpcbData = (DWORD)aLen;
            return ERROR_SUCCESS;
        }
        if (!lpcbData) return ERROR_INVALID_PARAMETER;

        if (*lpcbData < (DWORD)aLen) {
            *lpcbData = (DWORD)aLen;
            return ERROR_MORE_DATA;
        }
        *lpcbData = (DWORD)aLen;
        WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)buf.data(), -1, (LPSTR)lpData, aLen, NULL, NULL);
        return ERROR_SUCCESS;
    } else {
        if (!lpData) {
            if (lpcbData) *lpcbData = cbData;
            return ERROR_SUCCESS;
        }
        if (!lpcbData) return ERROR_INVALID_PARAMETER;

        if (*lpcbData < cbData) {
            *lpcbData = cbData;
            return ERROR_MORE_DATA;
        }
        return Hook_RegQueryValueExW(hKey, lpValueName ? wName : NULL, lpReserved, &dwType, lpData, lpcbData);
    }
}

LSTATUS WINAPI Hook_RegFlushKey(HKEY hKey) {
    if (g_processExiting.load(std::memory_order_relaxed)) {
        if (IS_FAKE_HKEY(hKey)) return ERROR_SUCCESS;
        return Orig_RegFlushKey ? Orig_RegFlushKey(hKey) : ERROR_SUCCESS;
    }
    if (g_insideHook) return Orig_RegFlushKey ? Orig_RegFlushKey(hKey) : ERROR_SUCCESS;
    HookGuard guard;

    if (IS_FAKE_HKEY(hKey)) {
        SaveRegistryToIni();
        return ERROR_SUCCESS;
    }
    return Orig_RegFlushKey ? Orig_RegFlushKey(hKey) : ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName) {
    if (g_insideHook) return Orig_RegDeleteValueW(hKey, lpValueName);
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) return Orig_RegDeleteValueW ? Orig_RegDeleteValueW(hKey, lpValueName) : ERROR_INVALID_HANDLE;

    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        auto hIt = g_openHandles.find(hKey);
        if (hIt != g_openHandles.end()) {
            g_vRegData[hIt->second.subKey].erase(lpValueName ? lpValueName : L"");
        } else {
            return ERROR_INVALID_HANDLE;
        }
    }
    SaveRegistryToIni();
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteValueA(HKEY hKey, LPCSTR lpValueName) {
    if (g_insideHook) return Orig_RegDeleteValueA ? Orig_RegDeleteValueA(hKey, lpValueName) : ERROR_INVALID_HANDLE;
    wchar_t wName[512] = { 0 };
    if (lpValueName) MultiByteToWideChar(CP_ACP, 0, lpValueName, -1, wName, 512);
    return Hook_RegDeleteValueW(hKey, lpValueName ? wName : NULL);
}

LSTATUS WINAPI Hook_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    if (g_insideHook) return Orig_RegDeleteKeyW(hKey, lpSubKey);
    HookGuard guard;

    std::wstring base = RootKeyToString(hKey);
    if (base.empty()) return Orig_RegDeleteKeyW ? Orig_RegDeleteKeyW(hKey, lpSubKey) : ERROR_INVALID_HANDLE;

    std::wstring sub = lpSubKey ? lpSubKey : L"";
    std::wstring full = NormalizeRegKey(sub.empty() ? base : (base + L"\\" + sub));

    if (!ShouldVirtualizeKey(full)) return Orig_RegDeleteKeyW ? Orig_RegDeleteKeyW(hKey, lpSubKey) : ERROR_SUCCESS;

    {
        std::lock_guard<std::recursive_mutex> lock(g_regMutex);
        g_vRegData.erase(full);

        std::wstring prefix = full + L"\\";
        for (auto it = g_vRegData.begin(); it != g_vRegData.end(); ) {
            if (StartsWithI(it->first, prefix)) {
                it = g_vRegData.erase(it);
            } else {
                ++it;
            }
        }
    }
    SaveRegistryToIni();
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey) {
    if (g_insideHook) return Orig_RegDeleteKeyA ? Orig_RegDeleteKeyA(hKey, lpSubKey) : ERROR_INVALID_HANDLE;
    wchar_t wSub[1024] = { 0 };
    if (lpSubKey) MultiByteToWideChar(CP_ACP, 0, lpSubKey, -1, wSub, 1024);
    return Hook_RegDeleteKeyW(hKey, lpSubKey ? wSub : NULL);
}

LSTATUS WINAPI Hook_RegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    return Hook_RegDeleteKeyA(hKey, lpSubKey);
}

LSTATUS WINAPI Hook_RegDeleteKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName) {
    if (g_insideHook) return Orig_RegDeleteKeyValueW ? Orig_RegDeleteKeyValueW(hKey, lpSubKey, lpValueName) : ERROR_CALL_NOT_IMPLEMENTED;
    HookGuard guard;

    HKEY hSub = NULL;
    LSTATUS st = Hook_RegOpenKeyExW(hKey, lpSubKey, 0, KEY_SET_VALUE, &hSub);
    if (st != ERROR_SUCCESS) return st;

    LSTATUS res = Hook_RegDeleteValueW(hSub, lpValueName);
    Hook_RegCloseKey(hSub);
    return res;
}

LSTATUS WINAPI Hook_RegDeleteKeyValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName) {
    if (g_insideHook) return Orig_RegDeleteKeyValueA ? Orig_RegDeleteKeyValueA(hKey, lpSubKey, lpValueName) : ERROR_CALL_NOT_IMPLEMENTED;
    wchar_t wSub[1024] = { 0 };
    wchar_t wVal[512] = { 0 };
    if (lpSubKey) MultiByteToWideChar(CP_ACP, 0, lpSubKey, -1, wSub, 1024);
    if (lpValueName) MultiByteToWideChar(CP_ACP, 0, lpValueName, -1, wVal, 512);

    return Hook_RegDeleteKeyValueW(hKey, lpSubKey ? wSub : NULL, lpValueName ? wVal : NULL);
}

LSTATUS WINAPI Hook_RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName,
    LPDWORD lpReserved, LPWSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime) {
    if (g_insideHook) return Orig_RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) return Orig_RegEnumKeyExW(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    auto hIt = g_openHandles.find(hKey);
    if (hIt == g_openHandles.end()) return ERROR_INVALID_HANDLE;

    std::wstring parent = hIt->second.subKey + L"\\";
    std::vector<std::wstring> subKeys;
    for (const auto& kv : g_vRegData) {
        if (kv.first.length() > parent.length() && StartsWithI(kv.first, parent)) {
            std::wstring rest = kv.first.substr(parent.length());
            size_t slash = rest.find(L'\\');
            std::wstring directSub = (slash == std::wstring::npos) ? rest : rest.substr(0, slash);
            if (std::find(subKeys.begin(), subKeys.end(), directSub) == subKeys.end()) {
                subKeys.push_back(directSub);
            }
        }
    }

    if (dwIndex >= subKeys.size()) return ERROR_NO_MORE_ITEMS;

    if (lpName && lpcchName) {
        if (*lpcchName <= subKeys[dwIndex].length()) {
            *lpcchName = (DWORD)subKeys[dwIndex].length();
            return ERROR_MORE_DATA;
        }
        wcscpy_s(lpName, *lpcchName, subKeys[dwIndex].c_str());
        *lpcchName = (DWORD)subKeys[dwIndex].length();
    }
    if (lpcchClass && lpClass) *lpcchClass = 0;
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName,
    LPDWORD lpReserved, LPSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime) {
    if (g_insideHook) return Orig_RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);
    if (!IS_FAKE_HKEY(hKey)) return Orig_RegEnumKeyExA(hKey, dwIndex, lpName, lpcchName, lpReserved, lpClass, lpcchClass, lpftLastWriteTime);

    wchar_t wName[512] = { 0 };
    DWORD cchW = 512;
    LSTATUS st = Hook_RegEnumKeyExW(hKey, dwIndex, wName, &cchW, lpReserved, NULL, NULL, lpftLastWriteTime);
    if (st == ERROR_SUCCESS) {
        int aNeeded = WideCharToMultiByte(CP_ACP, 0, wName, -1, NULL, 0, NULL, NULL);
        if (!lpName || !lpcchName || *lpcchName < (DWORD)aNeeded) {
            if (lpcchName) *lpcchName = (DWORD)max(0, aNeeded - 1);
            return ERROR_MORE_DATA;
        }
        WideCharToMultiByte(CP_ACP, 0, wName, -1, lpName, *lpcchName, NULL, NULL);
        *lpcchName = (DWORD)(aNeeded - 1);
    }
    return st;
}

LSTATUS WINAPI Hook_RegEnumKeyW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, DWORD cchName) {
    DWORD cch = cchName;
    return Hook_RegEnumKeyExW(hKey, dwIndex, lpName, &cch, NULL, NULL, NULL, NULL);
}

LSTATUS WINAPI Hook_RegEnumKeyA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD cchName) {
    DWORD cch = cchName;
    return Hook_RegEnumKeyExA(hKey, dwIndex, lpName, &cch, NULL, NULL, NULL, NULL);
}

LSTATUS WINAPI Hook_RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName,
    LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData) {
    if (g_insideHook) return Orig_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) return Orig_RegEnumValueW(hKey, dwIndex, lpValueName, lpcchValueName, lpReserved, lpType, lpData, lpcbData);

    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    auto hIt = g_openHandles.find(hKey);
    if (hIt == g_openHandles.end()) return ERROR_INVALID_HANDLE;

    auto kIt = g_vRegData.find(hIt->second.subKey);
    if (kIt == g_vRegData.end() || dwIndex >= kIt->second.size()) return ERROR_NO_MORE_ITEMS;

    auto it = kIt->second.begin();
    std::advance(it, dwIndex);

    if (lpcchValueName) {
        DWORD nameLen = (DWORD)it->first.length();
        if (lpValueName) {
            if (*lpcchValueName <= nameLen) {
                *lpcchValueName = nameLen;
                return ERROR_MORE_DATA;
            }
            wcsncpy_s(lpValueName, *lpcchValueName, it->first.c_str(), _TRUNCATE);
        }
        *lpcchValueName = nameLen;
    }

    if (lpType) *lpType = it->second.type;

    if (lpcbData) {
        DWORD sz = (DWORD)it->second.data.size();
        if (lpData) {
            if (*lpcbData < sz) {
                *lpcbData = sz;
                return ERROR_MORE_DATA;
            }
            if (sz > 0) memcpy(lpData, it->second.data.data(), sz);
        }
        *lpcbData = sz;
    }

    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved,
    LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues,
    LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime) {
    if (g_insideHook) return Orig_RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) return Orig_RegQueryInfoKeyW(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);

    std::lock_guard<std::recursive_mutex> lock(g_regMutex);
    auto hIt = g_openHandles.find(hKey);
    if (hIt == g_openHandles.end()) return ERROR_INVALID_HANDLE;

    std::wstring parent = hIt->second.subKey + L"\\";
    std::vector<std::wstring> subKeys;
    DWORD maxSubKeyLen = 0;
    for (const auto& kv : g_vRegData) {
        if (kv.first.length() > parent.length() && StartsWithI(kv.first, parent)) {
            std::wstring rest = kv.first.substr(parent.length());
            size_t slash = rest.find(L'\\');
            std::wstring directSub = (slash == std::wstring::npos) ? rest : rest.substr(0, slash);
            if (std::find(subKeys.begin(), subKeys.end(), directSub) == subKeys.end()) {
                subKeys.push_back(directSub);
                if (directSub.length() > maxSubKeyLen) maxSubKeyLen = (DWORD)directSub.length();
            }
        }
    }

    auto kIt = g_vRegData.find(hIt->second.subKey);
    DWORD valCount = 0;
    DWORD maxValNameLen = 0;
    DWORD maxValDataLen = 0;

    if (kIt != g_vRegData.end()) {
        valCount = (DWORD)kIt->second.size();
        for (const auto& v : kIt->second) {
            if (v.first.length() > maxValNameLen) maxValNameLen = (DWORD)v.first.length();
            if (v.second.data.size() > maxValDataLen) maxValDataLen = (DWORD)v.second.data.size();
        }
    }

    if (lpcSubKeys) *lpcSubKeys = (DWORD)subKeys.size();
    if (lpcbMaxSubKeyLen) *lpcbMaxSubKeyLen = maxSubKeyLen;
    if (lpcbMaxClassLen) *lpcbMaxClassLen = 0;
    if (lpcValues) *lpcValues = valCount;
    if (lpcbMaxValueNameLen) *lpcbMaxValueNameLen = maxValNameLen;
    if (lpcbMaxValueLen) *lpcbMaxValueLen = maxValDataLen;
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = 0;
    if (lpcchClass && lpClass) *lpcchClass = 0;
    return ERROR_SUCCESS;
}

LSTATUS WINAPI Hook_RegQueryInfoKeyA(HKEY hKey, LPSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved,
    LPDWORD lpcSubKeys, LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues,
    LPDWORD lpcbMaxValueNameLen, LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime) {
    if (g_insideHook) return Orig_RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
    if (!IS_FAKE_HKEY(hKey)) return Orig_RegQueryInfoKeyA ? Orig_RegQueryInfoKeyA(hKey, lpClass, lpcchClass, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime) : ERROR_INVALID_HANDLE;
    return Hook_RegQueryInfoKeyW(hKey, NULL, NULL, lpReserved, lpcSubKeys, lpcbMaxSubKeyLen, lpcbMaxClassLen, lpcValues, lpcbMaxValueNameLen, lpcbMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
}

typedef LSTATUS (WINAPI *pfn_RegGetValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
typedef LSTATUS (WINAPI *pfn_RegSetKeyValueW)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPCVOID, DWORD);
typedef LSTATUS (WINAPI *pfn_RegDeleteKeyExW)(HKEY, LPCWSTR, REGSAM, DWORD);
typedef DWORD   (WINAPI *pfn_GetTempPath2W)(DWORD, LPWSTR);

static pfn_RegGetValueW    Orig_RegGetValueW    = NULL;
static pfn_RegSetKeyValueW Orig_RegSetKeyValueW = NULL;
static pfn_RegDeleteKeyExW Orig_RegDeleteKeyExW = NULL;
static pfn_GetTempPath2W   Orig_GetTempPath2W   = NULL;

typedef LSTATUS (WINAPI *pfn_RegGetValueA)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);
static pfn_RegGetValueA Orig_RegGetValueA = NULL;

typedef HANDLE (WINAPI *pfn_CreateFile2)(LPCWSTR, DWORD, DWORD, DWORD, PVOID);
static pfn_CreateFile2 Orig_CreateFile2 = NULL;

HANDLE WINAPI Hook_CreateFile2(LPCWSTR lpFileName, DWORD dwAccess, DWORD dwShare, DWORD dwDisp, PVOID pParams) {
    if (!Orig_CreateFile2) return INVALID_HANDLE_VALUE;
    if (g_insideHook || !lpFileName) return Orig_CreateFile2(lpFileName, dwAccess, dwShare, dwDisp, pParams);
    HookGuard guard;

    bool isWrite = (dwAccess & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA)) != 0;
    std::wstring finalPath = RedirectPath(lpFileName, isWrite);
    HANDLE h = Orig_CreateFile2(finalPath.c_str(), dwAccess, dwShare, dwDisp, pParams);
    DWORD err = GetLastError();

    if (h == INVALID_HANDLE_VALUE) {
        LogFormat(LOG_LVL_FAIL, L"[FILE FAILED] CreateFile2: \"%s\" -> \"%s\" (Access: 0x%08X, Disp: %u, Error: %lu)", 
            lpFileName, finalPath.c_str(), dwAccess, dwDisp, err);
    } else {
        LogFormat(LOG_LVL_ALL, L"[FILE OK] CreateFile2: \"%s\" -> \"%s\" (Access: 0x%08X)", 
            lpFileName, finalPath.c_str(), dwAccess);
    }

    SetLastError(err);
    return h;
}

LSTATUS WINAPI Hook_RegGetValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) {
    if (g_insideHook) {
        return Orig_RegGetValueW ? Orig_RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData) : ERROR_CALL_NOT_IMPLEMENTED;
    }
    HookGuard guard;

    
    if (!IS_FAKE_HKEY(hKey)) {
        return Orig_RegGetValueW ? Orig_RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData) : ERROR_CALL_NOT_IMPLEMENTED;
    }

    HKEY hTargetKey = hKey;
    bool needClose = false;

    if (lpSubKey && lpSubKey[0] != L'\0') {
        LSTATUS st = Hook_RegOpenKeyExW(hKey, lpSubKey, 0, KEY_QUERY_VALUE, &hTargetKey);
        if (st != ERROR_SUCCESS) return st;
        needClose = true;
    }

    DWORD actualType = 0;
    LSTATUS res = Hook_RegQueryValueExW(hTargetKey, lpValue, NULL, &actualType, (LPBYTE)pvData, pcbData);
    if (res == ERROR_SUCCESS) {
        if (pdwType) *pdwType = actualType;

        bool typeMatch = true;
        if (dwFlags & 0x0000FFFF) {
            DWORD typeMask = 0;
            switch (actualType) {
            case REG_NONE:      typeMask = 0x00000001; break;
            case REG_SZ:        typeMask = 0x00000002; break;
            case REG_EXPAND_SZ: typeMask = 0x00000004; break;
            case REG_BINARY:    typeMask = 0x00000008; break;
            case REG_DWORD:     typeMask = 0x00000010; break;
            case REG_MULTI_SZ:  typeMask = 0x00000020; break;
            case REG_QWORD:     typeMask = 0x00000040; break;
            default:            typeMatch = false; break;
            }
            if (typeMask && !(dwFlags & typeMask)) {
                typeMatch = false;
            }
        }

        if (!typeMatch) {
            res = ERROR_UNSUPPORTED_TYPE;
        } else if (actualType == REG_EXPAND_SZ && !(dwFlags & 0x10000000) && pvData && pcbData) {
            std::wstring rawStr((wchar_t*)pvData);
            wchar_t expBuf[32768];
            DWORD expLen = ExpandEnvironmentStringsW(rawStr.c_str(), expBuf, 32768);
            if (expLen > 0 && expLen * sizeof(wchar_t) <= *pcbData) {
                memcpy(pvData, expBuf, expLen * sizeof(wchar_t));
                *pcbData = expLen * sizeof(wchar_t);
            }
        }
    }

    if (needClose) {
        Hook_RegCloseKey(hTargetKey);
    }
    return res;
}

LSTATUS WINAPI Hook_RegGetValueA(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData) {
    if (g_insideHook) {
        return Orig_RegGetValueA ? Orig_RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData) : ERROR_CALL_NOT_IMPLEMENTED;
    }
    HookGuard guard;

    
    
    if (!IS_FAKE_HKEY(hKey)) {
        return Orig_RegGetValueA ? Orig_RegGetValueA(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData) : ERROR_CALL_NOT_IMPLEMENTED;
    }

    
    wchar_t wSubKey[1024] = { 0 };
    wchar_t wValue[512] = { 0 };
    if (lpSubKey) MultiByteToWideChar(CP_ACP, 0, lpSubKey, -1, wSubKey, 1024);
    if (lpValue) MultiByteToWideChar(CP_ACP, 0, lpValue, -1, wValue, 512);

    return Hook_RegGetValueW(hKey, lpSubKey ? wSubKey : NULL, lpValue ? wValue : NULL, dwFlags, pdwType, pvData, pcbData);
}




LSTATUS WINAPI Hook_RegSetKeyValueW(HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData) {
    if (g_insideHook) {
        return Orig_RegSetKeyValueW ? Orig_RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData) : ERROR_CALL_NOT_IMPLEMENTED;
    }
    HookGuard guard;

    if (!IS_FAKE_HKEY(hKey)) {
        if (!lpSubKey || lpSubKey[0] == L'\0') {
            return Orig_RegSetKeyValueW ? Orig_RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData) : ERROR_FILE_NOT_FOUND;
        }
        std::wstring base = RootKeyToString(hKey);
        if (!base.empty()) {
            std::wstring full = base + L"\\" + lpSubKey;
            if (!ShouldVirtualizeKey(full)) {
                return Orig_RegSetKeyValueW ? Orig_RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData) : ERROR_FILE_NOT_FOUND;
            }
        } else {
            return Orig_RegSetKeyValueW ? Orig_RegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData) : ERROR_FILE_NOT_FOUND;
        }
    }

    HKEY hTargetKey = hKey;
    bool needClose = false;

    if (lpSubKey && lpSubKey[0] != L'\0') {
        LSTATUS st = Hook_RegCreateKeyExW(hKey, lpSubKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hTargetKey, NULL);
        if (st != ERROR_SUCCESS) return st;
        needClose = true;
    }

    LSTATUS res = Hook_RegSetValueExW(hTargetKey, lpValueName, 0, dwType, (const BYTE*)lpData, cbData);

    if (needClose) {
        Hook_RegCloseKey(hTargetKey);
    }
    return res;
}

LSTATUS WINAPI Hook_RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    return Hook_RegDeleteKeyW(hKey, lpSubKey);
}

DWORD WINAPI Hook_GetTempPath2W(DWORD nBufferLength, LPWSTR lpBuffer) {
    return Hook_GetTempPathW(nBufferLength, lpBuffer);
}

BOOL WINAPI Hook_DeviceIoControl(
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
) {
    if (g_insideHook) {
        return Orig_DeviceIoControl ? 
            Orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped) : 
            FALSE;
    }
    HookGuard guard;

    BOOL res = Orig_DeviceIoControl ? 
        Orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped) : 
        FALSE;

    
    
    if (dwIoControlCode == IOCTL_STORAGE_QUERY_PROPERTY && lpInBuffer && nInBufferSize >= sizeof(STORAGE_PROPERTY_QUERY)) {
        PSTORAGE_PROPERTY_QUERY pQuery = (PSTORAGE_PROPERTY_QUERY)lpInBuffer;
        if (pQuery->PropertyId == StorageDeviceSeekPenaltyProperty && lpOutBuffer && nOutBufferSize >= sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR)) {
            PDEVICE_SEEK_PENALTY_DESCRIPTOR pDesc = (PDEVICE_SEEK_PENALTY_DESCRIPTOR)lpOutBuffer;
            pDesc->Version = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
            pDesc->Size = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
            pDesc->IncursSeekPenalty = FALSE; 
            if (lpBytesReturned) *lpBytesReturned = sizeof(DEVICE_SEEK_PENALTY_DESCRIPTOR);
            return TRUE;
        }
    }

    return res;
}

void WINAPI Hook_ExitProcess(UINT uExitCode) {
    
    g_processExiting.store(true, std::memory_order_release);
    SafeSaveOnExit();

    if (Orig_ExitProcess) Orig_ExitProcess(uExitCode);
    else ExitProcess(uExitCode);
}

typedef DWORD (WINAPI *pfn_GetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);
typedef DWORD (WINAPI *pfn_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
static pfn_GetEnvironmentVariableW Orig_GetEnvironmentVariableW = NULL;
static pfn_GetEnvironmentVariableA Orig_GetEnvironmentVariableA = NULL;

DWORD WINAPI Hook_GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize) {
    if (g_insideHook || !lpName) return Orig_GetEnvironmentVariableW ? Orig_GetEnvironmentVariableW(lpName, lpBuffer, nSize) : 0;
    HookGuard guard;

    std::wstring target;
    if (_wcsicmp(lpName, L"APPDATA") == 0) {
        target = g_portableDir + L"\\AppData\\Roaming";
    } else if (_wcsicmp(lpName, L"LOCALAPPDATA") == 0) {
        target = g_portableDir + L"\\AppData\\Local";
    } else if (_wcsicmp(lpName, L"USERPROFILE") == 0) {
        target = g_portableDir + L"\\UserProfile";
    } else if (_wcsicmp(lpName, L"PROGRAMDATA") == 0) {
        target = g_portableDir + L"\\ProgramData";
    } else if (_wcsicmp(lpName, L"TEMP") == 0 || _wcsicmp(lpName, L"TMP") == 0) {
        target = g_portableDir + L"\\Temp";
    }

    if (!target.empty()) {
        EnsureDirectoryTree(target, true);
        DWORD len = (DWORD)target.length();
        if (nSize <= len) {
            return len + 1;
        }
        if (lpBuffer) {
            wcscpy_s(lpBuffer, nSize, target.c_str());
            return len;
        }
    }

    return Orig_GetEnvironmentVariableW ? Orig_GetEnvironmentVariableW(lpName, lpBuffer, nSize) : 0;
}

DWORD WINAPI Hook_GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize) {
    if (g_insideHook || !lpName) return Orig_GetEnvironmentVariableA ? Orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize) : 0;
    HookGuard guard;

    
    if (_stricmp(lpName, "APPDATA") != 0 &&
        _stricmp(lpName, "LOCALAPPDATA") != 0 &&
        _stricmp(lpName, "USERPROFILE") != 0 &&
        _stricmp(lpName, "PROGRAMDATA") != 0 &&
        _stricmp(lpName, "TEMP") != 0 &&
        _stricmp(lpName, "TMP") != 0) {
        return Orig_GetEnvironmentVariableA ? Orig_GetEnvironmentVariableA(lpName, lpBuffer, nSize) : 0;
    }

    wchar_t wName[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, lpName, -1, wName, MAX_PATH);

    DWORD wNeeded = Hook_GetEnvironmentVariableW(wName, NULL, 0);
    if (wNeeded == 0) return 0;

    std::vector<wchar_t> wBuf(wNeeded);
    DWORD wRes = Hook_GetEnvironmentVariableW(wName, wBuf.data(), wNeeded);
    if (wRes == 0) return 0;

    int aLenNeeded = WideCharToMultiByte(CP_ACP, 0, wBuf.data(), -1, NULL, 0, NULL, NULL);
    if (aLenNeeded <= 0) return 0;

    if (nSize < (DWORD)aLenNeeded || !lpBuffer) {
        return (DWORD)aLenNeeded;
    }

    WideCharToMultiByte(CP_ACP, 0, wBuf.data(), -1, lpBuffer, nSize, NULL, NULL);
    return (DWORD)(aLenNeeded - 1);
}





static HMODULE g_hRealVersionDll = NULL;
static HMODULE g_hRealWinmmDll   = NULL;
static HMODULE g_hRealDwmapiDll  = NULL;
static HMODULE g_hRealMscoreeDll = NULL;
static HMODULE g_hRealD3D9Dll    = NULL;
static HMODULE g_hRealDxgiDll    = NULL;
static std::recursive_mutex g_proxyMutex;

void InitProxy();

#ifdef PlaySound
#undef PlaySound
#endif
#ifdef sndPlaySound
#undef sndPlaySound
#endif

#if defined(_M_IX86) || defined(__i386__)

    #define PROXY_STUB(name) \
        static FARPROC p_##name = NULL; \
        extern "C" __declspec(naked) void proxy_##name() { \
            __asm jmp dword ptr [p_##name] \
        }
    #define LINKER_EXPORT(name) __pragma(comment(linker, "/EXPORT:" #name "=_proxy_" #name))
    #define RESOLVE_PROXY(hDll, name) \
        if (hDll) { \
            p_##name = GetProcAddress(hDll, #name); \
            if (!p_##name) { \
                LogFormat(LOG_LVL_FAIL, L"[PROXY ERROR] GetProcAddress failed for %S (Error: %lu)", #name, GetLastError()); \
            } \
        }

#else

    static inline void PatchProxyThunk(void* pProxyFunc, void* pRealTarget) {
        if (!pProxyFunc || !pRealTarget) return;
        DWORD oldProt;
        if (VirtualProtect(pProxyFunc, 14, PAGE_EXECUTE_READWRITE, &oldProt)) {
            uint8_t* p = (uint8_t*)pProxyFunc;
            p[0] = 0xFF;
            p[1] = 0x25;
            *(int32_t*)&p[2] = 0;
            *(uint64_t*)&p[6] = (uint64_t)pRealTarget;
            VirtualProtect(pProxyFunc, 14, oldProt, &oldProt);
            FlushInstructionCache(GetCurrentProcess(), pProxyFunc, 14);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[PROXY ERROR] VirtualProtect failed for thunk patch (Error: %lu)", GetLastError());
        }
    }

    #define PROXY_STUB(name) \
        static FARPROC p_##name = NULL; \
        extern "C" void proxy_##name() { \
            volatile int uniqueId = __COUNTER__; (void)uniqueId; \
            volatile FARPROC p = p_##name; \
            if (!p) { \
                LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Invoked missing system export: " #name); \
                MessageBoxA(NULL, "Failed to route system API call: " #name, "Portable Engine Fatal Error", MB_ICONERROR); \
                ExitProcess(ERROR_PROC_NOT_FOUND); \
            } \
            __nop(); __nop(); __nop(); __nop(); \
        }
    #define LINKER_EXPORT(name) __pragma(comment(linker, "/EXPORT:" #name "=proxy_" #name))
    #define RESOLVE_PROXY(hDll, name) \
        if (hDll) { \
            p_##name = GetProcAddress(hDll, #name); \
            if (!p_##name) { \
                LogFormat(LOG_LVL_FAIL, L"[PROXY ERROR] GetProcAddress failed for %S (Error: %lu)", #name, GetLastError()); \
            } else { \
                PatchProxyThunk((void*)proxy_##name, (void*)p_##name); \
            } \
        }

#endif


PROXY_STUB(GetFileVersionInfoA)
PROXY_STUB(GetFileVersionInfoByHandle)
PROXY_STUB(GetFileVersionInfoExA)
PROXY_STUB(GetFileVersionInfoExW)
PROXY_STUB(GetFileVersionInfoSizeA)
PROXY_STUB(GetFileVersionInfoSizeExA)
PROXY_STUB(GetFileVersionInfoSizeExW)
PROXY_STUB(GetFileVersionInfoSizeW)
PROXY_STUB(GetFileVersionInfoSizeByHandle)
PROXY_STUB(GetFileVersionInfoW)
PROXY_STUB(VerFindFileA)
PROXY_STUB(VerFindFileW)
PROXY_STUB(VerInstallFileA)
PROXY_STUB(VerInstallFileW)
PROXY_STUB(VerLanguageNameA)
PROXY_STUB(VerLanguageNameW)
PROXY_STUB(VerQueryValueA)
PROXY_STUB(VerQueryValueW)

LINKER_EXPORT(GetFileVersionInfoA)
LINKER_EXPORT(GetFileVersionInfoByHandle)
LINKER_EXPORT(GetFileVersionInfoExA)
LINKER_EXPORT(GetFileVersionInfoExW)
LINKER_EXPORT(GetFileVersionInfoSizeA)
LINKER_EXPORT(GetFileVersionInfoSizeExA)
LINKER_EXPORT(GetFileVersionInfoSizeExW)
LINKER_EXPORT(GetFileVersionInfoSizeW)
LINKER_EXPORT(GetFileVersionInfoSizeByHandle)
LINKER_EXPORT(GetFileVersionInfoW)
LINKER_EXPORT(VerFindFileA)
LINKER_EXPORT(VerFindFileW)
LINKER_EXPORT(VerInstallFileA)
LINKER_EXPORT(VerInstallFileW)
LINKER_EXPORT(VerLanguageNameA)
LINKER_EXPORT(VerLanguageNameW)
LINKER_EXPORT(VerQueryValueA)
LINKER_EXPORT(VerQueryValueW)


PROXY_STUB(CloseDriver)
PROXY_STUB(DefDriverProc)
PROXY_STUB(DriverCallback)
PROXY_STUB(DrvGetModuleHandle)
PROXY_STUB(GetDriverModuleHandle)
PROXY_STUB(NotifyCallbackData)
PROXY_STUB(OpenDriver)
PROXY_STUB(PlaySound)
PROXY_STUB(PlaySoundA)
PROXY_STUB(PlaySoundW)
PROXY_STUB(SendDriverMessage)
PROXY_STUB(WOW32DriverCallback)
PROXY_STUB(WOW32ResolveMultiMediaHandle)
PROXY_STUB(WOWAppExit)
PROXY_STUB(auxGetDevCapsA)
PROXY_STUB(auxGetDevCapsW)
PROXY_STUB(auxGetNumDevs)
PROXY_STUB(auxGetVolume)
PROXY_STUB(auxOutMessage)
PROXY_STUB(auxSetVolume)
PROXY_STUB(joyConfigChanged)
PROXY_STUB(joyGetDevCapsA)
PROXY_STUB(joyGetDevCapsW)
PROXY_STUB(joyGetNumDevs)
PROXY_STUB(joyGetPos)
PROXY_STUB(joyGetPosEx)
PROXY_STUB(joyGetThreshold)
PROXY_STUB(joyReleaseCapture)
PROXY_STUB(joySetCapture)
PROXY_STUB(joySetThreshold)
PROXY_STUB(mciDriverNotify)
PROXY_STUB(mciDriverYield)
PROXY_STUB(mciExecute)
PROXY_STUB(mciFreeCommandResource)
PROXY_STUB(mciGetCreatorTask)
PROXY_STUB(mciGetDeviceIDA)
PROXY_STUB(mciGetDeviceIDFromElementIDA)
PROXY_STUB(mciGetDeviceIDFromElementIDW)
PROXY_STUB(mciGetDeviceIDW)
PROXY_STUB(mciGetDriverData)
PROXY_STUB(mciGetErrorStringA)
PROXY_STUB(mciGetErrorStringW)
PROXY_STUB(mciGetYieldProc)
PROXY_STUB(mciSendCommandA)
PROXY_STUB(mciSendCommandW)
PROXY_STUB(mciSendStringA)
PROXY_STUB(mciSendStringW)
PROXY_STUB(mciSetDriverData)
PROXY_STUB(mciSetYieldProc)
PROXY_STUB(midiConnect)
PROXY_STUB(midiDisconnect)
PROXY_STUB(midiInAddBuffer)
PROXY_STUB(midiInClose)
PROXY_STUB(midiInGetDevCapsA)
PROXY_STUB(midiInGetDevCapsW)
PROXY_STUB(midiInGetErrorTextA)
PROXY_STUB(midiInGetErrorTextW)
PROXY_STUB(midiInGetID)
PROXY_STUB(midiInGetNumDevs)
PROXY_STUB(midiInMessage)
PROXY_STUB(midiInOpen)
PROXY_STUB(midiInPrepareHeader)
PROXY_STUB(midiInReset)
PROXY_STUB(midiInStart)
PROXY_STUB(midiInStop)
PROXY_STUB(midiInUnprepareHeader)
PROXY_STUB(midiOutCacheDrumPatches)
PROXY_STUB(midiOutCachePatches)
PROXY_STUB(midiOutClose)
PROXY_STUB(midiOutGetDevCapsA)
PROXY_STUB(midiOutGetDevCapsW)
PROXY_STUB(midiOutGetErrorTextA)
PROXY_STUB(midiOutGetErrorTextW)
PROXY_STUB(midiOutGetID)
PROXY_STUB(midiOutGetNumDevs)
PROXY_STUB(midiOutGetVolume)
PROXY_STUB(midiOutLongMsg)
PROXY_STUB(midiOutMessage)
PROXY_STUB(midiOutOpen)
PROXY_STUB(midiOutPrepareHeader)
PROXY_STUB(midiOutReset)
PROXY_STUB(midiOutSetVolume)
PROXY_STUB(midiOutShortMsg)
PROXY_STUB(midiOutUnprepareHeader)
PROXY_STUB(midiStreamClose)
PROXY_STUB(midiStreamOpen)
PROXY_STUB(midiStreamOut)
PROXY_STUB(midiStreamPause)
PROXY_STUB(midiStreamPosition)
PROXY_STUB(midiStreamProperty)
PROXY_STUB(midiStreamRestart)
PROXY_STUB(midiStreamStop)
PROXY_STUB(mixerClose)
PROXY_STUB(mixerGetControlDetailsA)
PROXY_STUB(mixerGetControlDetailsW)
PROXY_STUB(mixerGetDevCapsA)
PROXY_STUB(mixerGetDevCapsW)
PROXY_STUB(mixerGetID)
PROXY_STUB(mixerGetLineControlsA)
PROXY_STUB(mixerGetLineControlsW)
PROXY_STUB(mixerGetLineInfoA)
PROXY_STUB(mixerGetLineInfoW)
PROXY_STUB(mixerGetNumDevs)
PROXY_STUB(mixerMessage)
PROXY_STUB(mixerOpen)
PROXY_STUB(mixerSetControlDetails)
PROXY_STUB(mmDrvInstall)
PROXY_STUB(mmGetCurrentTask)
PROXY_STUB(mmTaskBlock)
PROXY_STUB(mmTaskCreate)
PROXY_STUB(mmTaskSignal)
PROXY_STUB(mmTaskYield)
PROXY_STUB(mmioAdvance)
PROXY_STUB(mmioAscend)
PROXY_STUB(mmioClose)
PROXY_STUB(mmioCreateChunk)
PROXY_STUB(mmioDescend)
PROXY_STUB(mmioFlush)
PROXY_STUB(mmioGetInfo)
PROXY_STUB(mmioInstallIOProcA)
PROXY_STUB(mmioInstallIOProcW)
PROXY_STUB(mmioOpenA)
PROXY_STUB(mmioOpenW)
PROXY_STUB(mmioRead)
PROXY_STUB(mmioRenameA)
PROXY_STUB(mmioRenameW)
PROXY_STUB(mmioSeek)
PROXY_STUB(mmioSendMessage)
PROXY_STUB(mmioSetBuffer)
PROXY_STUB(mmioSetInfo)
PROXY_STUB(mmioStringToFOURCCA)
PROXY_STUB(mmioStringToFOURCCW)
PROXY_STUB(mmioWrite)
PROXY_STUB(sndPlaySoundA)
PROXY_STUB(sndPlaySoundW)
PROXY_STUB(timeBeginPeriod)
PROXY_STUB(timeEndPeriod)
PROXY_STUB(timeGetDevCaps)
PROXY_STUB(timeGetSystemTime)
PROXY_STUB(timeGetTime)
PROXY_STUB(timeKillEvent)
PROXY_STUB(timeSetEvent)
PROXY_STUB(waveInAddBuffer)
PROXY_STUB(waveInClose)
PROXY_STUB(waveInGetDevCapsA)
PROXY_STUB(waveInGetDevCapsW)
PROXY_STUB(waveInGetErrorTextA)
PROXY_STUB(waveInGetErrorTextW)
PROXY_STUB(waveInGetID)
PROXY_STUB(waveInGetNumDevs)
PROXY_STUB(waveInGetPosition)
PROXY_STUB(waveInMessage)
PROXY_STUB(waveInOpen)
PROXY_STUB(waveInPrepareHeader)
PROXY_STUB(waveInReset)
PROXY_STUB(waveInStart)
PROXY_STUB(waveInStop)
PROXY_STUB(waveInUnprepareHeader)
PROXY_STUB(waveOutBreakLoop)
PROXY_STUB(waveOutClose)
PROXY_STUB(waveOutGetDevCapsA)
PROXY_STUB(waveOutGetDevCapsW)
PROXY_STUB(waveOutGetErrorTextA)
PROXY_STUB(waveOutGetErrorTextW)
PROXY_STUB(waveOutGetID)
PROXY_STUB(waveOutGetNumDevs)
PROXY_STUB(waveOutGetPitch)
PROXY_STUB(waveOutGetPlaybackRate)
PROXY_STUB(waveOutGetPosition)
PROXY_STUB(waveOutGetVolume)
PROXY_STUB(waveOutMessage)
PROXY_STUB(waveOutOpen)
PROXY_STUB(waveOutPause)
PROXY_STUB(waveOutPrepareHeader)
PROXY_STUB(waveOutReset)
PROXY_STUB(waveOutRestart)
PROXY_STUB(waveOutSetPitch)
PROXY_STUB(waveOutSetPlaybackRate)
PROXY_STUB(waveOutSetVolume)
PROXY_STUB(waveOutUnprepareHeader)
PROXY_STUB(waveOutWrite)

LINKER_EXPORT(CloseDriver)
LINKER_EXPORT(DefDriverProc)
LINKER_EXPORT(DriverCallback)
LINKER_EXPORT(DrvGetModuleHandle)
LINKER_EXPORT(GetDriverModuleHandle)
LINKER_EXPORT(NotifyCallbackData)
LINKER_EXPORT(OpenDriver)
LINKER_EXPORT(PlaySound)
LINKER_EXPORT(PlaySoundA)
LINKER_EXPORT(PlaySoundW)
LINKER_EXPORT(SendDriverMessage)
LINKER_EXPORT(WOW32DriverCallback)
LINKER_EXPORT(WOW32ResolveMultiMediaHandle)
LINKER_EXPORT(WOWAppExit)
LINKER_EXPORT(auxGetDevCapsA)
LINKER_EXPORT(auxGetDevCapsW)
LINKER_EXPORT(auxGetNumDevs)
LINKER_EXPORT(auxGetVolume)
LINKER_EXPORT(auxOutMessage)
LINKER_EXPORT(auxSetVolume)
LINKER_EXPORT(joyConfigChanged)
LINKER_EXPORT(joyGetDevCapsA)
LINKER_EXPORT(joyGetDevCapsW)
LINKER_EXPORT(joyGetNumDevs)
LINKER_EXPORT(joyGetPos)
LINKER_EXPORT(joyGetPosEx)
LINKER_EXPORT(joyGetThreshold)
LINKER_EXPORT(joyReleaseCapture)
LINKER_EXPORT(joySetCapture)
LINKER_EXPORT(joySetThreshold)
LINKER_EXPORT(mciDriverNotify)
LINKER_EXPORT(mciDriverYield)
LINKER_EXPORT(mciExecute)
LINKER_EXPORT(mciFreeCommandResource)
LINKER_EXPORT(mciGetCreatorTask)
LINKER_EXPORT(mciGetDeviceIDA)
LINKER_EXPORT(mciGetDeviceIDFromElementIDA)
LINKER_EXPORT(mciGetDeviceIDFromElementIDW)
LINKER_EXPORT(mciGetDeviceIDW)
LINKER_EXPORT(mciGetDriverData)
LINKER_EXPORT(mciGetErrorStringA)
LINKER_EXPORT(mciGetErrorStringW)
LINKER_EXPORT(mciGetYieldProc)
LINKER_EXPORT(mciSendCommandA)
LINKER_EXPORT(mciSendCommandW)
LINKER_EXPORT(mciSendStringA)
LINKER_EXPORT(mciSendStringW)
LINKER_EXPORT(mciSetDriverData)
LINKER_EXPORT(mciSetYieldProc)
LINKER_EXPORT(midiConnect)
LINKER_EXPORT(midiDisconnect)
LINKER_EXPORT(midiInAddBuffer)
LINKER_EXPORT(midiInClose)
LINKER_EXPORT(midiInGetDevCapsA)
LINKER_EXPORT(midiInGetDevCapsW)
LINKER_EXPORT(midiInGetErrorTextA)
LINKER_EXPORT(midiInGetErrorTextW)
LINKER_EXPORT(midiInGetID)
LINKER_EXPORT(midiInGetNumDevs)
LINKER_EXPORT(midiInMessage)
LINKER_EXPORT(midiInOpen)
LINKER_EXPORT(midiInPrepareHeader)
LINKER_EXPORT(midiInReset)
LINKER_EXPORT(midiInStart)
LINKER_EXPORT(midiInStop)
LINKER_EXPORT(midiInUnprepareHeader)
LINKER_EXPORT(midiOutCacheDrumPatches)
LINKER_EXPORT(midiOutCachePatches)
LINKER_EXPORT(midiOutClose)
LINKER_EXPORT(midiOutGetDevCapsA)
LINKER_EXPORT(midiOutGetDevCapsW)
LINKER_EXPORT(midiOutGetErrorTextA)
LINKER_EXPORT(midiOutGetErrorTextW)
LINKER_EXPORT(midiOutGetID)
LINKER_EXPORT(midiOutGetNumDevs)
LINKER_EXPORT(midiOutGetVolume)
LINKER_EXPORT(midiOutLongMsg)
LINKER_EXPORT(midiOutMessage)
LINKER_EXPORT(midiOutOpen)
LINKER_EXPORT(midiOutPrepareHeader)
LINKER_EXPORT(midiOutReset)
LINKER_EXPORT(midiOutSetVolume)
LINKER_EXPORT(midiOutShortMsg)
LINKER_EXPORT(midiOutUnprepareHeader)
LINKER_EXPORT(midiStreamClose)
LINKER_EXPORT(midiStreamOpen)
LINKER_EXPORT(midiStreamOut)
LINKER_EXPORT(midiStreamPause)
LINKER_EXPORT(midiStreamPosition)
LINKER_EXPORT(midiStreamProperty)
LINKER_EXPORT(midiStreamRestart)
LINKER_EXPORT(midiStreamStop)
LINKER_EXPORT(mixerClose)
LINKER_EXPORT(mixerGetControlDetailsA)
LINKER_EXPORT(mixerGetControlDetailsW)
LINKER_EXPORT(mixerGetDevCapsA)
LINKER_EXPORT(mixerGetDevCapsW)
LINKER_EXPORT(mixerGetID)
LINKER_EXPORT(mixerGetLineControlsA)
LINKER_EXPORT(mixerGetLineControlsW)
LINKER_EXPORT(mixerGetLineInfoA)
LINKER_EXPORT(mixerGetLineInfoW)
LINKER_EXPORT(mixerGetNumDevs)
LINKER_EXPORT(mixerMessage)
LINKER_EXPORT(mixerOpen)
LINKER_EXPORT(mixerSetControlDetails)
LINKER_EXPORT(mmDrvInstall)
LINKER_EXPORT(mmGetCurrentTask)
LINKER_EXPORT(mmTaskBlock)
LINKER_EXPORT(mmTaskCreate)
LINKER_EXPORT(mmTaskSignal)
LINKER_EXPORT(mmTaskYield)
LINKER_EXPORT(mmioAdvance)
LINKER_EXPORT(mmioAscend)
LINKER_EXPORT(mmioClose)
LINKER_EXPORT(mmioCreateChunk)
LINKER_EXPORT(mmioDescend)
LINKER_EXPORT(mmioFlush)
LINKER_EXPORT(mmioGetInfo)
LINKER_EXPORT(mmioInstallIOProcA)
LINKER_EXPORT(mmioInstallIOProcW)
LINKER_EXPORT(mmioOpenA)
LINKER_EXPORT(mmioOpenW)
LINKER_EXPORT(mmioRead)
LINKER_EXPORT(mmioRenameA)
LINKER_EXPORT(mmioRenameW)
LINKER_EXPORT(mmioSeek)
LINKER_EXPORT(mmioSendMessage)
LINKER_EXPORT(mmioSetBuffer)
LINKER_EXPORT(mmioSetInfo)
LINKER_EXPORT(mmioStringToFOURCCA)
LINKER_EXPORT(mmioStringToFOURCCW)
LINKER_EXPORT(mmioWrite)
LINKER_EXPORT(sndPlaySoundA)
LINKER_EXPORT(sndPlaySoundW)
LINKER_EXPORT(timeBeginPeriod)
LINKER_EXPORT(timeEndPeriod)
LINKER_EXPORT(timeGetDevCaps)
LINKER_EXPORT(timeGetSystemTime)
LINKER_EXPORT(timeGetTime)
LINKER_EXPORT(timeKillEvent)
LINKER_EXPORT(timeSetEvent)
LINKER_EXPORT(waveInAddBuffer)
LINKER_EXPORT(waveInClose)
LINKER_EXPORT(waveInGetDevCapsA)
LINKER_EXPORT(waveInGetDevCapsW)
LINKER_EXPORT(waveInGetErrorTextA)
LINKER_EXPORT(waveInGetErrorTextW)
LINKER_EXPORT(waveInGetID)
LINKER_EXPORT(waveInGetNumDevs)
LINKER_EXPORT(waveInGetPosition)
LINKER_EXPORT(waveInMessage)
LINKER_EXPORT(waveInOpen)
LINKER_EXPORT(waveInPrepareHeader)
LINKER_EXPORT(waveInReset)
LINKER_EXPORT(waveInStart)
LINKER_EXPORT(waveInStop)
LINKER_EXPORT(waveInUnprepareHeader)
LINKER_EXPORT(waveOutBreakLoop)
LINKER_EXPORT(waveOutClose)
LINKER_EXPORT(waveOutGetDevCapsA)
LINKER_EXPORT(waveOutGetDevCapsW)
LINKER_EXPORT(waveOutGetErrorTextA)
LINKER_EXPORT(waveOutGetErrorTextW)
LINKER_EXPORT(waveOutGetID)
LINKER_EXPORT(waveOutGetNumDevs)
LINKER_EXPORT(waveOutGetPitch)
LINKER_EXPORT(waveOutGetPlaybackRate)
LINKER_EXPORT(waveOutGetPosition)
LINKER_EXPORT(waveOutGetVolume)
LINKER_EXPORT(waveOutMessage)
LINKER_EXPORT(waveOutOpen)
LINKER_EXPORT(waveOutPause)
LINKER_EXPORT(waveOutPrepareHeader)
LINKER_EXPORT(waveOutReset)
LINKER_EXPORT(waveOutRestart)
LINKER_EXPORT(waveOutSetPitch)
LINKER_EXPORT(waveOutSetPlaybackRate)
LINKER_EXPORT(waveOutSetVolume)
LINKER_EXPORT(waveOutUnprepareHeader)
LINKER_EXPORT(waveOutWrite)


PROXY_STUB(DwmAttachMilContent)
PROXY_STUB(DwmDefWindowProc)
PROXY_STUB(DwmDetachMilContent)
PROXY_STUB(DwmEnableBlurBehindWindow)
PROXY_STUB(DwmEnableComposition)
PROXY_STUB(DwmEnableMMCSS)
PROXY_STUB(DwmExtendFrameIntoClientArea)
PROXY_STUB(DwmFlush)
PROXY_STUB(DwmGetColorizationColor)
PROXY_STUB(DwmGetCompositionTimingInfo)
PROXY_STUB(DwmGetGraphicsStreamClient)
PROXY_STUB(DwmGetGraphicsStreamTransformHint)
PROXY_STUB(DwmGetTransportAttributes)
PROXY_STUB(DwmGetWindowAttribute)
PROXY_STUB(DwmInvalidateIconicBitmaps)
PROXY_STUB(DwmIsCompositionEnabled)
PROXY_STUB(DwmModifyPreviousDxFrameDuration)
PROXY_STUB(DwmQueryThumbnailSourceSize)
PROXY_STUB(DwmRegisterThumbnail)
PROXY_STUB(DwmRenderGesture)
PROXY_STUB(DwmSetDxFrameDuration)
PROXY_STUB(DwmSetIconicLivePreviewBitmap)
PROXY_STUB(DwmSetIconicThumbnail)
PROXY_STUB(DwmSetPresentParameters)
PROXY_STUB(DwmSetWindowAttribute)
PROXY_STUB(DwmShowContact)
PROXY_STUB(DwmTetherContact)
PROXY_STUB(DwmTransitionOwnedWindow)
PROXY_STUB(DwmUnregisterThumbnail)
PROXY_STUB(DwmUpdateThumbnailProperties)

LINKER_EXPORT(DwmAttachMilContent)
LINKER_EXPORT(DwmDefWindowProc)
LINKER_EXPORT(DwmDetachMilContent)
LINKER_EXPORT(DwmEnableBlurBehindWindow)
LINKER_EXPORT(DwmEnableComposition)
LINKER_EXPORT(DwmEnableMMCSS)
LINKER_EXPORT(DwmExtendFrameIntoClientArea)
LINKER_EXPORT(DwmFlush)
LINKER_EXPORT(DwmGetColorizationColor)
LINKER_EXPORT(DwmGetCompositionTimingInfo)
LINKER_EXPORT(DwmGetGraphicsStreamClient)
LINKER_EXPORT(DwmGetGraphicsStreamTransformHint)
LINKER_EXPORT(DwmGetTransportAttributes)
LINKER_EXPORT(DwmGetWindowAttribute)
LINKER_EXPORT(DwmInvalidateIconicBitmaps)
LINKER_EXPORT(DwmIsCompositionEnabled)
LINKER_EXPORT(DwmModifyPreviousDxFrameDuration)
LINKER_EXPORT(DwmQueryThumbnailSourceSize)
LINKER_EXPORT(DwmRegisterThumbnail)
LINKER_EXPORT(DwmRenderGesture)
LINKER_EXPORT(DwmSetDxFrameDuration)
LINKER_EXPORT(DwmSetIconicLivePreviewBitmap)
LINKER_EXPORT(DwmSetIconicThumbnail)
LINKER_EXPORT(DwmSetPresentParameters)
LINKER_EXPORT(DwmSetWindowAttribute)
LINKER_EXPORT(DwmShowContact)
LINKER_EXPORT(DwmTetherContact)
LINKER_EXPORT(DwmTransitionOwnedWindow)
LINKER_EXPORT(DwmUnregisterThumbnail)
LINKER_EXPORT(DwmUpdateThumbnailProperties)


PROXY_STUB(CLRCreateInstance)
PROXY_STUB(CallFunctionShim)
PROXY_STUB(CoEEShutDownCOM)
PROXY_STUB(CoInitializeCor)
PROXY_STUB(CoInitializeEE)
PROXY_STUB(CoUninitializeCor)
PROXY_STUB(CoUninitializeEE)
PROXY_STUB(CorBindToCurrentRuntime)
PROXY_STUB(CorBindToRuntime)
PROXY_STUB(CorBindToRuntimeByCfg)
PROXY_STUB(CorBindToRuntimeByPath)
PROXY_STUB(CorBindToRuntimeByPathEx)
PROXY_STUB(CorBindToRuntimeEx)
PROXY_STUB(CorBindToRuntimeHost)
PROXY_STUB(CorExitProcess)
PROXY_STUB(CorGetHostConfiguration)
PROXY_STUB(CorIsLatestSvr)
PROXY_STUB(CorMarkThreadInThreadPool)
PROXY_STUB(CreateConfigStream)
PROXY_STUB(CreateDebuggingInterfaceFromVersion)
PROXY_STUB(GetAssemblyMDImport)
PROXY_STUB(GetCLRIdentityManager)
PROXY_STUB(GetCORHost)
PROXY_STUB(GetCORRequiredVersion)
PROXY_STUB(GetCORSystemDirectory)
PROXY_STUB(GetCORVersion)
PROXY_STUB(GetCompileInfo)
PROXY_STUB(GetHostConfigurationFile)
PROXY_STUB(GetMetaDataInternalInterface)
PROXY_STUB(GetMetaDataInternalInterfaceFromPublic)
PROXY_STUB(GetMetaDataPublicInterfaceFromInternal)
PROXY_STUB(GetPermissionRequests)
PROXY_STUB(GetPrivateContextsPerfCounters)
PROXY_STUB(GetProcessRootGCHandles)
PROXY_STUB(GetRealProcAddress)
PROXY_STUB(GetRequestedRuntimeInfo)
PROXY_STUB(GetRequestedRuntimeVersion)
PROXY_STUB(GetRequestedRuntimeVersionForCLSID)
PROXY_STUB(GetTargetPlatform)
PROXY_STUB(GetVersionFromProcess)
PROXY_STUB(GetXContextHost)
PROXY_STUB(IEE)
PROXY_STUB(InitFusion)
PROXY_STUB(InitSSAutoEnterContext)
PROXY_STUB(InitSSAutoEnterContextInternal)
PROXY_STUB(InitUpdateAppCtx)
PROXY_STUB(InitXProcAutoEnterContext)
PROXY_STUB(InitXProcAutoEnterContextInternal)
PROXY_STUB(LoadLibraryShim)
PROXY_STUB(LoadLibraryWithCheck)
PROXY_STUB(LoadStringRC)
PROXY_STUB(LoadStringRCEx)
PROXY_STUB(LockClrVersion)
PROXY_STUB(LogHelp_TerminateOnAssert)
PROXY_STUB(PostError)
PROXY_STUB(ReOpenMetaDataWithObj)
PROXY_STUB(ReOpenMetaDataWithObjEx)
PROXY_STUB(RunDll32ShimW)
PROXY_STUB(RuntimeOpenImage)
PROXY_STUB(RuntimeReleaseHandle)
PROXY_STUB(SaveContextData)
PROXY_STUB(SetAddrOfCaptureThreadContext)
PROXY_STUB(SetAppDomainPolicy)
PROXY_STUB(SetCaptureThreadContextStatus)
PROXY_STUB(SetClrConfigValue)
PROXY_STUB(SetConcurrentGC)
PROXY_STUB(SetCorExitProcessHook)
PROXY_STUB(SetHostConfigurationFile)
PROXY_STUB(SetStartupFlags)
PROXY_STUB(ShellExecuteShimW)
PROXY_STUB(StrongNameErrorInfo)
PROXY_STUB(StrongNameFreeBuffer)
PROXY_STUB(StrongNameGetBlob)
PROXY_STUB(StrongNameGetBlobFromImage)
PROXY_STUB(StrongNameGetPublicKey)
PROXY_STUB(StrongNameGetPublicKeyFromImage)
PROXY_STUB(StrongNameHashNode)
PROXY_STUB(StrongNameKeyDelete)
PROXY_STUB(StrongNameKeyGen)
PROXY_STUB(StrongNameKeyGenEx)
PROXY_STUB(StrongNameKeyInstall)
PROXY_STUB(StrongNameSignatureGeneration)
PROXY_STUB(StrongNameSignatureGenerationEx)
PROXY_STUB(StrongNameSignatureSize)
PROXY_STUB(StrongNameSignatureVerification)
PROXY_STUB(StrongNameSignatureVerificationEx)
PROXY_STUB(StrongNameSignatureVerificationFromImage)
PROXY_STUB(StrongNameTokenFromAssembly)
PROXY_STUB(StrongNameTokenFromAssemblyEx)
PROXY_STUB(StrongNameTokenFromPublicKey)
PROXY_STUB(TranslateSecurityAttributes)
PROXY_STUB(UpdateAppCtx)
PROXY_STUB(_CorDllMain)
PROXY_STUB(_CorExeMain)
PROXY_STUB(_CorExeMain2)
PROXY_STUB(_CorImageUnloading)
PROXY_STUB(_CorValidateImage)

LINKER_EXPORT(CLRCreateInstance)
LINKER_EXPORT(CallFunctionShim)
LINKER_EXPORT(CoEEShutDownCOM)
LINKER_EXPORT(CoInitializeCor)
LINKER_EXPORT(CoInitializeEE)
LINKER_EXPORT(CoUninitializeCor)
LINKER_EXPORT(CoUninitializeEE)
LINKER_EXPORT(CorBindToCurrentRuntime)
LINKER_EXPORT(CorBindToRuntime)
LINKER_EXPORT(CorBindToRuntimeByCfg)
LINKER_EXPORT(CorBindToRuntimeByPath)
LINKER_EXPORT(CorBindToRuntimeByPathEx)
LINKER_EXPORT(CorBindToRuntimeEx)
LINKER_EXPORT(CorBindToRuntimeHost)
LINKER_EXPORT(CorExitProcess)
LINKER_EXPORT(CorGetHostConfiguration)
LINKER_EXPORT(CorIsLatestSvr)
LINKER_EXPORT(CorMarkThreadInThreadPool)
LINKER_EXPORT(CreateConfigStream)
LINKER_EXPORT(CreateDebuggingInterfaceFromVersion)
LINKER_EXPORT(GetAssemblyMDImport)
LINKER_EXPORT(GetCLRIdentityManager)
LINKER_EXPORT(GetCORHost)
LINKER_EXPORT(GetCORRequiredVersion)
LINKER_EXPORT(GetCORSystemDirectory)
LINKER_EXPORT(GetCORVersion)
LINKER_EXPORT(GetCompileInfo)
LINKER_EXPORT(GetHostConfigurationFile)
LINKER_EXPORT(GetMetaDataInternalInterface)
LINKER_EXPORT(GetMetaDataInternalInterfaceFromPublic)
LINKER_EXPORT(GetMetaDataPublicInterfaceFromInternal)
LINKER_EXPORT(GetPermissionRequests)
LINKER_EXPORT(GetPrivateContextsPerfCounters)
LINKER_EXPORT(GetProcessRootGCHandles)
LINKER_EXPORT(GetRealProcAddress)
LINKER_EXPORT(GetRequestedRuntimeInfo)
LINKER_EXPORT(GetRequestedRuntimeVersion)
LINKER_EXPORT(GetRequestedRuntimeVersionForCLSID)
LINKER_EXPORT(GetTargetPlatform)
LINKER_EXPORT(GetVersionFromProcess)
LINKER_EXPORT(GetXContextHost)
LINKER_EXPORT(IEE)
LINKER_EXPORT(InitFusion)
LINKER_EXPORT(InitSSAutoEnterContext)
LINKER_EXPORT(InitSSAutoEnterContextInternal)
LINKER_EXPORT(InitUpdateAppCtx)
LINKER_EXPORT(InitXProcAutoEnterContext)
LINKER_EXPORT(InitXProcAutoEnterContextInternal)
LINKER_EXPORT(LoadLibraryShim)
LINKER_EXPORT(LoadLibraryWithCheck)
LINKER_EXPORT(LoadStringRC)
LINKER_EXPORT(LoadStringRCEx)
LINKER_EXPORT(LockClrVersion)
LINKER_EXPORT(LogHelp_TerminateOnAssert)
LINKER_EXPORT(PostError)
LINKER_EXPORT(ReOpenMetaDataWithObj)
LINKER_EXPORT(ReOpenMetaDataWithObjEx)
LINKER_EXPORT(RunDll32ShimW)
LINKER_EXPORT(RuntimeOpenImage)
LINKER_EXPORT(RuntimeReleaseHandle)
LINKER_EXPORT(SaveContextData)
LINKER_EXPORT(SetAddrOfCaptureThreadContext)
LINKER_EXPORT(SetAppDomainPolicy)
LINKER_EXPORT(SetCaptureThreadContextStatus)
LINKER_EXPORT(SetClrConfigValue)
LINKER_EXPORT(SetConcurrentGC)
LINKER_EXPORT(SetCorExitProcessHook)
LINKER_EXPORT(SetHostConfigurationFile)
LINKER_EXPORT(SetStartupFlags)
LINKER_EXPORT(ShellExecuteShimW)
LINKER_EXPORT(StrongNameErrorInfo)
LINKER_EXPORT(StrongNameFreeBuffer)
LINKER_EXPORT(StrongNameGetBlob)
LINKER_EXPORT(StrongNameGetBlobFromImage)
LINKER_EXPORT(StrongNameGetPublicKey)
LINKER_EXPORT(StrongNameGetPublicKeyFromImage)
LINKER_EXPORT(StrongNameHashNode)
LINKER_EXPORT(StrongNameKeyDelete)
LINKER_EXPORT(StrongNameKeyGen)
LINKER_EXPORT(StrongNameKeyGenEx)
LINKER_EXPORT(StrongNameKeyInstall)
LINKER_EXPORT(StrongNameSignatureGeneration)
LINKER_EXPORT(StrongNameSignatureGenerationEx)
LINKER_EXPORT(StrongNameSignatureSize)
LINKER_EXPORT(StrongNameSignatureVerification)
LINKER_EXPORT(StrongNameSignatureVerificationEx)
LINKER_EXPORT(StrongNameSignatureVerificationFromImage)
LINKER_EXPORT(StrongNameTokenFromAssembly)
LINKER_EXPORT(StrongNameTokenFromAssemblyEx)
LINKER_EXPORT(StrongNameTokenFromPublicKey)
LINKER_EXPORT(TranslateSecurityAttributes)
LINKER_EXPORT(UpdateAppCtx)
LINKER_EXPORT(_CorDllMain)
LINKER_EXPORT(_CorExeMain)
LINKER_EXPORT(_CorExeMain2)
LINKER_EXPORT(_CorImageUnloading)
LINKER_EXPORT(_CorValidateImage)


PROXY_STUB(Direct3DCreate9)
PROXY_STUB(Direct3DCreate9Ex)
PROXY_STUB(D3DPERF_BeginEvent)
PROXY_STUB(D3DPERF_EndEvent)
PROXY_STUB(D3DPERF_GetStatus)
PROXY_STUB(D3DPERF_QueryRepeatFrame)
PROXY_STUB(D3DPERF_SetMarker)
PROXY_STUB(D3DPERF_SetOptions)
PROXY_STUB(D3DPERF_SetRegion)
PROXY_STUB(DebugSetLevel)
PROXY_STUB(DebugSetMute)
PROXY_STUB(Direct3DShaderValidatorCreate9)
PROXY_STUB(PSGPError)
PROXY_STUB(PSGPSampleTexture)

LINKER_EXPORT(Direct3DCreate9)
LINKER_EXPORT(Direct3DCreate9Ex)
LINKER_EXPORT(D3DPERF_BeginEvent)
LINKER_EXPORT(D3DPERF_EndEvent)
LINKER_EXPORT(D3DPERF_GetStatus)
LINKER_EXPORT(D3DPERF_QueryRepeatFrame)
LINKER_EXPORT(D3DPERF_SetMarker)
LINKER_EXPORT(D3DPERF_SetOptions)
LINKER_EXPORT(D3DPERF_SetRegion)
LINKER_EXPORT(DebugSetLevel)
LINKER_EXPORT(DebugSetMute)
LINKER_EXPORT(Direct3DShaderValidatorCreate9)
LINKER_EXPORT(PSGPError)
LINKER_EXPORT(PSGPSampleTexture)


PROXY_STUB(CreateDXGIFactory)
PROXY_STUB(CreateDXGIFactory1)
PROXY_STUB(CreateDXGIFactory2)
PROXY_STUB(DXGIDumpJournal)
PROXY_STUB(DXGIGetDebugInterface1)
PROXY_STUB(DXGIReportAdapterConfiguration)

LINKER_EXPORT(CreateDXGIFactory)
LINKER_EXPORT(CreateDXGIFactory1)
LINKER_EXPORT(CreateDXGIFactory2)
LINKER_EXPORT(DXGIDumpJournal)
LINKER_EXPORT(DXGIGetDebugInterface1)
LINKER_EXPORT(DXGIReportAdapterConfiguration)

void InitProxy() {
    std::lock_guard<std::recursive_mutex> lock(g_proxyMutex);

    wchar_t modulePath[MAX_PATH];
    HMODULE hSelf = NULL;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)InitProxy, &hSelf)) {
        LogFormat(LOG_LVL_FAIL, L"[PROXY ERROR] GetModuleHandleExW failed for proxy DLL (Error: %lu)", GetLastError());
        return;
    }
    GetModuleFileNameW(hSelf, modulePath, MAX_PATH);

    std::wstring dllName = PathFindFileNameW(modulePath);
    wchar_t sysDir[MAX_PATH];
    GetSystemDirectoryW(sysDir, MAX_PATH);

    if (_wcsicmp(dllName.c_str(), L"version.dll") == 0 && !g_hRealVersionDll) {
        std::wstring realDll = std::wstring(sysDir) + L"\\version.dll";
        g_hRealVersionDll = LoadLibraryW(realDll.c_str());
        if (g_hRealVersionDll) {
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoA);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoByHandle);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoExA);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoExW);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoSizeA);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoSizeExA);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoSizeExW);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoSizeW);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoSizeByHandle);
            RESOLVE_PROXY(g_hRealVersionDll, GetFileVersionInfoW);
            RESOLVE_PROXY(g_hRealVersionDll, VerFindFileA);
            RESOLVE_PROXY(g_hRealVersionDll, VerFindFileW);
            RESOLVE_PROXY(g_hRealVersionDll, VerInstallFileA);
            RESOLVE_PROXY(g_hRealVersionDll, VerInstallFileW);
            RESOLVE_PROXY(g_hRealVersionDll, VerLanguageNameA);
            RESOLVE_PROXY(g_hRealVersionDll, VerLanguageNameW);
            RESOLVE_PROXY(g_hRealVersionDll, VerQueryValueA);
            RESOLVE_PROXY(g_hRealVersionDll, VerQueryValueW);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system version.dll (Error: %lu)", GetLastError());
        }
    } else if (_wcsicmp(dllName.c_str(), L"winmm.dll") == 0 && !g_hRealWinmmDll) {
        std::wstring realWinmm = std::wstring(sysDir) + L"\\winmm.dll";
        g_hRealWinmmDll = LoadLibraryW(realWinmm.c_str());
        if (g_hRealWinmmDll) {
            RESOLVE_PROXY(g_hRealWinmmDll, CloseDriver);
            RESOLVE_PROXY(g_hRealWinmmDll, DefDriverProc);
            RESOLVE_PROXY(g_hRealWinmmDll, DriverCallback);
            RESOLVE_PROXY(g_hRealWinmmDll, DrvGetModuleHandle);
            RESOLVE_PROXY(g_hRealWinmmDll, GetDriverModuleHandle);
            RESOLVE_PROXY(g_hRealWinmmDll, NotifyCallbackData);
            RESOLVE_PROXY(g_hRealWinmmDll, OpenDriver);
            RESOLVE_PROXY(g_hRealWinmmDll, PlaySound);
            RESOLVE_PROXY(g_hRealWinmmDll, PlaySoundA);
            RESOLVE_PROXY(g_hRealWinmmDll, PlaySoundW);
            RESOLVE_PROXY(g_hRealWinmmDll, SendDriverMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, WOW32DriverCallback);
            RESOLVE_PROXY(g_hRealWinmmDll, WOW32ResolveMultiMediaHandle);
            RESOLVE_PROXY(g_hRealWinmmDll, WOWAppExit);
            RESOLVE_PROXY(g_hRealWinmmDll, auxGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, auxGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, auxGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, auxGetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, auxOutMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, auxSetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, joyConfigChanged);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetPos);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetPosEx);
            RESOLVE_PROXY(g_hRealWinmmDll, joyGetThreshold);
            RESOLVE_PROXY(g_hRealWinmmDll, joyReleaseCapture);
            RESOLVE_PROXY(g_hRealWinmmDll, joySetCapture);
            RESOLVE_PROXY(g_hRealWinmmDll, joySetThreshold);
            RESOLVE_PROXY(g_hRealWinmmDll, mciDriverNotify);
            RESOLVE_PROXY(g_hRealWinmmDll, mciDriverYield);
            RESOLVE_PROXY(g_hRealWinmmDll, mciExecute);
            RESOLVE_PROXY(g_hRealWinmmDll, mciFreeCommandResource);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetCreatorTask);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetDeviceIDA);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetDeviceIDFromElementIDA);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetDeviceIDFromElementIDW);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetDeviceIDW);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetDriverData);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetErrorStringA);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetErrorStringW);
            RESOLVE_PROXY(g_hRealWinmmDll, mciGetYieldProc);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSendCommandA);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSendCommandW);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSendStringA);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSendStringW);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSetDriverData);
            RESOLVE_PROXY(g_hRealWinmmDll, mciSetYieldProc);
            RESOLVE_PROXY(g_hRealWinmmDll, midiConnect);
            RESOLVE_PROXY(g_hRealWinmmDll, midiDisconnect);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInAddBuffer);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInClose);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetErrorTextA);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetErrorTextW);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetID);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInPrepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInReset);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInStart);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInStop);
            RESOLVE_PROXY(g_hRealWinmmDll, midiInUnprepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutCacheDrumPatches);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutCachePatches);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutClose);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetErrorTextA);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetErrorTextW);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetID);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutGetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutLongMsg);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutPrepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutReset);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutSetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutShortMsg);
            RESOLVE_PROXY(g_hRealWinmmDll, midiOutUnprepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamClose);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamOut);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamPause);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamPosition);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamProperty);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamRestart);
            RESOLVE_PROXY(g_hRealWinmmDll, midiStreamStop);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerClose);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetControlDetailsA);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetControlDetailsW);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetID);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetLineControlsA);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetLineControlsW);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetLineInfoA);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetLineInfoW);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, mixerSetControlDetails);
            RESOLVE_PROXY(g_hRealWinmmDll, mmDrvInstall);
            RESOLVE_PROXY(g_hRealWinmmDll, mmGetCurrentTask);
            RESOLVE_PROXY(g_hRealWinmmDll, mmTaskBlock);
            RESOLVE_PROXY(g_hRealWinmmDll, mmTaskCreate);
            RESOLVE_PROXY(g_hRealWinmmDll, mmTaskSignal);
            RESOLVE_PROXY(g_hRealWinmmDll, mmTaskYield);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioAdvance);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioAscend);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioClose);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioCreateChunk);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioDescend);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioFlush);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioGetInfo);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioInstallIOProcA);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioInstallIOProcW);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioOpenA);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioOpenW);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioRead);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioRenameA);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioRenameW);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioSeek);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioSendMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioSetBuffer);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioSetInfo);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioStringToFOURCCA);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioStringToFOURCCW);
            RESOLVE_PROXY(g_hRealWinmmDll, mmioWrite);
            RESOLVE_PROXY(g_hRealWinmmDll, sndPlaySoundA);
            RESOLVE_PROXY(g_hRealWinmmDll, sndPlaySoundW);
            RESOLVE_PROXY(g_hRealWinmmDll, timeBeginPeriod);
            RESOLVE_PROXY(g_hRealWinmmDll, timeEndPeriod);
            RESOLVE_PROXY(g_hRealWinmmDll, timeGetDevCaps);
            RESOLVE_PROXY(g_hRealWinmmDll, timeGetSystemTime);
            RESOLVE_PROXY(g_hRealWinmmDll, timeGetTime);
            RESOLVE_PROXY(g_hRealWinmmDll, timeKillEvent);
            RESOLVE_PROXY(g_hRealWinmmDll, timeSetEvent);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInAddBuffer);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInClose);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetErrorTextA);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetErrorTextW);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetID);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInGetPosition);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInPrepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInReset);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInStart);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInStop);
            RESOLVE_PROXY(g_hRealWinmmDll, waveInUnprepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutBreakLoop);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutClose);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetDevCapsA);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetDevCapsW);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetErrorTextA);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetErrorTextW);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetID);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetNumDevs);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetPitch);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetPlaybackRate);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetPosition);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutGetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutMessage);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutOpen);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutPause);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutPrepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutReset);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutRestart);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutSetPitch);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutSetPlaybackRate);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutSetVolume);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutUnprepareHeader);
            RESOLVE_PROXY(g_hRealWinmmDll, waveOutWrite);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system winmm.dll (Error: %lu)", GetLastError());
        }
    } else if (_wcsicmp(dllName.c_str(), L"dwmapi.dll") == 0 && !g_hRealDwmapiDll) {
        std::wstring realDwmapi = std::wstring(sysDir) + L"\\dwmapi.dll";
        g_hRealDwmapiDll = LoadLibraryW(realDwmapi.c_str());
        if (g_hRealDwmapiDll) {
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmAttachMilContent);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmDefWindowProc);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmDetachMilContent);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmEnableBlurBehindWindow);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmEnableComposition);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmEnableMMCSS);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmExtendFrameIntoClientArea);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmFlush);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetColorizationColor);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetCompositionTimingInfo);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetGraphicsStreamClient);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetGraphicsStreamTransformHint);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetTransportAttributes);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmGetWindowAttribute);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmInvalidateIconicBitmaps);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmIsCompositionEnabled);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmModifyPreviousDxFrameDuration);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmQueryThumbnailSourceSize);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmRegisterThumbnail);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmRenderGesture);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmSetDxFrameDuration);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmSetIconicLivePreviewBitmap);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmSetIconicThumbnail);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmSetPresentParameters);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmSetWindowAttribute);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmShowContact);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmTetherContact);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmTransitionOwnedWindow);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmUnregisterThumbnail);
            RESOLVE_PROXY(g_hRealDwmapiDll, DwmUpdateThumbnailProperties);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system dwmapi.dll (Error: %lu)", GetLastError());
        }
    } else if (_wcsicmp(dllName.c_str(), L"mscoree.dll") == 0 && !g_hRealMscoreeDll) {
        std::wstring realMscoree = std::wstring(sysDir) + L"\\mscoree.dll";
        g_hRealMscoreeDll = LoadLibraryW(realMscoree.c_str());
        if (g_hRealMscoreeDll) {
            RESOLVE_PROXY(g_hRealMscoreeDll, CLRCreateInstance);
            RESOLVE_PROXY(g_hRealMscoreeDll, CallFunctionShim);
            RESOLVE_PROXY(g_hRealMscoreeDll, CoEEShutDownCOM);
            RESOLVE_PROXY(g_hRealMscoreeDll, CoInitializeCor);
            RESOLVE_PROXY(g_hRealMscoreeDll, CoInitializeEE);
            RESOLVE_PROXY(g_hRealMscoreeDll, CoUninitializeCor);
            RESOLVE_PROXY(g_hRealMscoreeDll, CoUninitializeEE);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToCurrentRuntime);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntime);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntimeByCfg);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntimeByPath);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntimeByPathEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntimeEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorBindToRuntimeHost);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorExitProcess);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorGetHostConfiguration);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorIsLatestSvr);
            RESOLVE_PROXY(g_hRealMscoreeDll, CorMarkThreadInThreadPool);
            RESOLVE_PROXY(g_hRealMscoreeDll, CreateConfigStream);
            RESOLVE_PROXY(g_hRealMscoreeDll, CreateDebuggingInterfaceFromVersion);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetAssemblyMDImport);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCLRIdentityManager);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCORHost);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCORRequiredVersion);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCORSystemDirectory);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCORVersion);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetCompileInfo);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetHostConfigurationFile);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetMetaDataInternalInterface);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetMetaDataInternalInterfaceFromPublic);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetMetaDataPublicInterfaceFromInternal);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetPermissionRequests);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetPrivateContextsPerfCounters);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetProcessRootGCHandles);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetRealProcAddress);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetRequestedRuntimeInfo);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetRequestedRuntimeVersion);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetRequestedRuntimeVersionForCLSID);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetTargetPlatform);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetVersionFromProcess);
            RESOLVE_PROXY(g_hRealMscoreeDll, GetXContextHost);
            RESOLVE_PROXY(g_hRealMscoreeDll, IEE);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitFusion);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitSSAutoEnterContext);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitSSAutoEnterContextInternal);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitUpdateAppCtx);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitXProcAutoEnterContext);
            RESOLVE_PROXY(g_hRealMscoreeDll, InitXProcAutoEnterContextInternal);
            RESOLVE_PROXY(g_hRealMscoreeDll, LoadLibraryShim);
            RESOLVE_PROXY(g_hRealMscoreeDll, LoadLibraryWithCheck);
            RESOLVE_PROXY(g_hRealMscoreeDll, LoadStringRC);
            RESOLVE_PROXY(g_hRealMscoreeDll, LoadStringRCEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, LockClrVersion);
            RESOLVE_PROXY(g_hRealMscoreeDll, LogHelp_TerminateOnAssert);
            RESOLVE_PROXY(g_hRealMscoreeDll, PostError);
            RESOLVE_PROXY(g_hRealMscoreeDll, ReOpenMetaDataWithObj);
            RESOLVE_PROXY(g_hRealMscoreeDll, ReOpenMetaDataWithObjEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, RunDll32ShimW);
            RESOLVE_PROXY(g_hRealMscoreeDll, RuntimeOpenImage);
            RESOLVE_PROXY(g_hRealMscoreeDll, RuntimeReleaseHandle);
            RESOLVE_PROXY(g_hRealMscoreeDll, SaveContextData);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetAddrOfCaptureThreadContext);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetAppDomainPolicy);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetCaptureThreadContextStatus);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetClrConfigValue);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetConcurrentGC);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetCorExitProcessHook);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetHostConfigurationFile);
            RESOLVE_PROXY(g_hRealMscoreeDll, SetStartupFlags);
            RESOLVE_PROXY(g_hRealMscoreeDll, ShellExecuteShimW);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameErrorInfo);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameFreeBuffer);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameGetBlob);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameGetBlobFromImage);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameGetPublicKey);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameGetPublicKeyFromImage);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameHashNode);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameKeyDelete);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameKeyGen);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameKeyGenEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameKeyInstall);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureGeneration);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureGenerationEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureSize);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureVerification);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureVerificationEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameSignatureVerificationFromImage);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameTokenFromAssembly);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameTokenFromAssemblyEx);
            RESOLVE_PROXY(g_hRealMscoreeDll, StrongNameTokenFromPublicKey);
            RESOLVE_PROXY(g_hRealMscoreeDll, TranslateSecurityAttributes);
            RESOLVE_PROXY(g_hRealMscoreeDll, UpdateAppCtx);
            RESOLVE_PROXY(g_hRealMscoreeDll, _CorDllMain);
            RESOLVE_PROXY(g_hRealMscoreeDll, _CorExeMain);
            RESOLVE_PROXY(g_hRealMscoreeDll, _CorExeMain2);
            RESOLVE_PROXY(g_hRealMscoreeDll, _CorImageUnloading);
            RESOLVE_PROXY(g_hRealMscoreeDll, _CorValidateImage);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system mscoree.dll (Error: %lu)", GetLastError());
        }
    } else if (_wcsicmp(dllName.c_str(), L"d3d9.dll") == 0 && !g_hRealD3D9Dll) {
        std::wstring realD3D9 = std::wstring(sysDir) + L"\\d3d9.dll";
        g_hRealD3D9Dll = LoadLibraryW(realD3D9.c_str());
        if (g_hRealD3D9Dll) {
            RESOLVE_PROXY(g_hRealD3D9Dll, Direct3DCreate9);
            RESOLVE_PROXY(g_hRealD3D9Dll, Direct3DCreate9Ex);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_BeginEvent);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_EndEvent);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_GetStatus);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_QueryRepeatFrame);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_SetMarker);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_SetOptions);
            RESOLVE_PROXY(g_hRealD3D9Dll, D3DPERF_SetRegion);
            RESOLVE_PROXY(g_hRealD3D9Dll, DebugSetLevel);
            RESOLVE_PROXY(g_hRealD3D9Dll, DebugSetMute);
            RESOLVE_PROXY(g_hRealD3D9Dll, Direct3DShaderValidatorCreate9);
            RESOLVE_PROXY(g_hRealD3D9Dll, PSGPError);
            RESOLVE_PROXY(g_hRealD3D9Dll, PSGPSampleTexture);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system d3d9.dll (Error: %lu)", GetLastError());
        }
    } else if (_wcsicmp(dllName.c_str(), L"dxgi.dll") == 0 && !g_hRealDxgiDll) {
        std::wstring realDxgi = std::wstring(sysDir) + L"\\dxgi.dll";
        g_hRealDxgiDll = LoadLibraryW(realDxgi.c_str());
        if (g_hRealDxgiDll) {
            RESOLVE_PROXY(g_hRealDxgiDll, CreateDXGIFactory);
            RESOLVE_PROXY(g_hRealDxgiDll, CreateDXGIFactory1);
            RESOLVE_PROXY(g_hRealDxgiDll, CreateDXGIFactory2);
            RESOLVE_PROXY(g_hRealDxgiDll, DXGIDumpJournal);
            RESOLVE_PROXY(g_hRealDxgiDll, DXGIGetDebugInterface1);
            RESOLVE_PROXY(g_hRealDxgiDll, DXGIReportAdapterConfiguration);
        } else {
            LogFormat(LOG_LVL_FAIL, L"[FATAL PROXY] Failed to load system dxgi.dll (Error: %lu)", GetLastError());
        }
    }
}





void HookExport(HMODULE hPrimary, HMODULE hSecondary, const char* funcName, void* hookFunc, void** origTrampoline) {
    void* pProc = NULL;
    if (hPrimary) pProc = (void*)GetProcAddress(hPrimary, funcName);
    if (!pProc && hSecondary) pProc = (void*)GetProcAddress(hSecondary, funcName);
    if (pProc) {
        CreateHook(pProc, hookFunc, origTrampoline);
    }
}

typedef int (WINAPI *pfn_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef int (WINAPI *pfn_MessageBoxW)(HWND, LPCWSTR, LPCWSTR, UINT);
static pfn_MessageBoxA Orig_MessageBoxA = NULL;
static pfn_MessageBoxW Orig_MessageBoxW = NULL;

int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    
    LogFormat(LOG_LVL_FAIL, L"[POPUP INTERCEPTED] Caption: \"%S\" | Text: \"%S\"", 
        lpCaption ? lpCaption : "None", lpText ? lpText : "None");

    
    if (!g_oepReached.load(std::memory_order_relaxed)) {
        LogFormat(LOG_LVL_FAIL, L"[POPUP BLOCKED] Suppressed modal dialog during startup to prevent 0xc0000142 crash.");
        return IDOK;
    }

    return Orig_MessageBoxA ? Orig_MessageBoxA(hWnd, lpText, lpCaption, uType) : IDOK;
}

int WINAPI Hook_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    LogFormat(LOG_LVL_FAIL, L"[POPUP INTERCEPTED] Caption: \"%s\" | Text: \"%s\"", 
        lpCaption ? lpCaption : L"None", lpText ? lpText : L"None");

    if (!g_oepReached.load(std::memory_order_relaxed)) {
        LogFormat(LOG_LVL_FAIL, L"[POPUP BLOCKED] Suppressed modal dialog during startup to prevent 0xc0000142 crash.");
        return IDOK;
    }

    return Orig_MessageBoxW ? Orig_MessageBoxW(hWnd, lpText, lpCaption, uType) : IDOK;
}


void InstallAllHooks() {
	HMODULE hUser32     = GetModuleHandleW(L"user32.dll");
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE hAdvapi32   = GetModuleHandleW(L"advapi32.dll");
	HMODULE hKernel32   = GetModuleHandleW(L"kernel32.dll");
    HMODULE hShell32    = GetModuleHandleW(L"shell32.dll");

    
    if (hUser32) {
        HookExport(hUser32, NULL, "MessageBoxA", (void*)Hook_MessageBoxA, (void**)&Orig_MessageBoxA);
        HookExport(hUser32, NULL, "MessageBoxW", (void*)Hook_MessageBoxW, (void**)&Orig_MessageBoxW);
    }

    
    HookExport(hKernelBase, hAdvapi32, "RegOpenKeyW",          (void*)Hook_RegOpenKeyW,          (void**)&Orig_RegOpenKeyW);
    HookExport(hKernelBase, hAdvapi32, "RegOpenKeyA",          (void*)Hook_RegOpenKeyA,          (void**)&Orig_RegOpenKeyA);
    HookExport(hKernelBase, hAdvapi32, "RegOpenKeyExW",        (void*)Hook_RegOpenKeyExW,        (void**)&Orig_RegOpenKeyExW);
    HookExport(hKernelBase, hAdvapi32, "RegOpenKeyExA",        (void*)Hook_RegOpenKeyExA,        (void**)&Orig_RegOpenKeyExA);
    HookExport(hKernelBase, hAdvapi32, "RegCreateKeyExW",      (void*)Hook_RegCreateKeyExW,      (void**)&Orig_RegCreateKeyExW);
    HookExport(hKernelBase, hAdvapi32, "RegCreateKeyExA",      (void*)Hook_RegCreateKeyExA,      (void**)&Orig_RegCreateKeyExA);
    HookExport(hKernelBase, hAdvapi32, "RegCloseKey",          (void*)Hook_RegCloseKey,          (void**)&Orig_RegCloseKey);
    HookExport(hKernelBase, hAdvapi32, "RegFlushKey",          (void*)Hook_RegFlushKey,          (void**)&Orig_RegFlushKey);
    HookExport(hKernelBase, hAdvapi32, "RegQueryValueExW",     (void*)Hook_RegQueryValueExW,     (void**)&Orig_RegQueryValueExW);
    HookExport(hKernelBase, hAdvapi32, "RegQueryValueExA",     (void*)Hook_RegQueryValueExA,     (void**)&Orig_RegQueryValueExA);
    HookExport(hKernelBase, hAdvapi32, "RegSetValueExW",       (void*)Hook_RegSetValueExW,       (void**)&Orig_RegSetValueExW);
    HookExport(hKernelBase, hAdvapi32, "RegSetValueExA",       (void*)Hook_RegSetValueExA,       (void**)&Orig_RegSetValueExA);
    HookExport(hKernelBase, hAdvapi32, "RegGetValueA",         (void*)Hook_RegGetValueA,         (void**)&Orig_RegGetValueA);
    HookExport(hKernelBase, hAdvapi32, "RegGetValueW",         (void*)Hook_RegGetValueW,         (void**)&Orig_RegGetValueW);
    HookExport(hKernelBase, hAdvapi32, "RegSetKeyValueW",      (void*)Hook_RegSetKeyValueW,      (void**)&Orig_RegSetKeyValueW);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteValueW",      (void*)Hook_RegDeleteValueW,      (void**)&Orig_RegDeleteValueW);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteValueA",      (void*)Hook_RegDeleteValueA,      (void**)&Orig_RegDeleteValueA);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyW",        (void*)Hook_RegDeleteKeyW,        (void**)&Orig_RegDeleteKeyW);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyA",        (void*)Hook_RegDeleteKeyA,        (void**)&Orig_RegDeleteKeyA);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyExW",      (void*)Hook_RegDeleteKeyExW,      (void**)&Orig_RegDeleteKeyExW);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyExA",      (void*)Hook_RegDeleteKeyExA,      (void**)&Orig_RegDeleteKeyExA);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyValueW",   (void*)Hook_RegDeleteKeyValueW,   (void**)&Orig_RegDeleteKeyValueW);
    HookExport(hKernelBase, hAdvapi32, "RegDeleteKeyValueA",   (void*)Hook_RegDeleteKeyValueA,   (void**)&Orig_RegDeleteKeyValueA);
    HookExport(hKernelBase, hAdvapi32, "RegEnumKeyW",          (void*)Hook_RegEnumKeyW,          (void**)&Orig_RegEnumKeyW);
    HookExport(hKernelBase, hAdvapi32, "RegEnumKeyA",          (void*)Hook_RegEnumKeyA,          (void**)&Orig_RegEnumKeyA);
    HookExport(hKernelBase, hAdvapi32, "RegEnumKeyExW",        (void*)Hook_RegEnumKeyExW,        (void**)&Orig_RegEnumKeyExW);
    HookExport(hKernelBase, hAdvapi32, "RegEnumKeyExA",        (void*)Hook_RegEnumKeyExA,        (void**)&Orig_RegEnumKeyExA);
    HookExport(hKernelBase, hAdvapi32, "RegEnumValueW",        (void*)Hook_RegEnumValueW,        (void**)&Orig_RegEnumValueW);
    HookExport(hKernelBase, hAdvapi32, "RegQueryInfoKeyW",     (void*)Hook_RegQueryInfoKeyW,     (void**)&Orig_RegQueryInfoKeyW);
    HookExport(hKernelBase, hAdvapi32, "RegQueryInfoKeyA",     (void*)Hook_RegQueryInfoKeyA,     (void**)&Orig_RegQueryInfoKeyA);

    if (hShell32) {
        HookExport(hShell32, NULL, "SHGetKnownFolderPath",       (void*)Hook_SHGetKnownFolderPath,       (void**)&Orig_SHGetKnownFolderPath);
        HookExport(hShell32, NULL, "SHGetFolderPathW",           (void*)Hook_SHGetFolderPathW,           (void**)&Orig_SHGetFolderPathW);
        HookExport(hShell32, NULL, "SHGetFolderPathA",           (void*)Hook_SHGetFolderPathA,           (void**)&Orig_SHGetFolderPathA);
        HookExport(hShell32, NULL, "SHGetSpecialFolderPathW",    (void*)Hook_SHGetSpecialFolderPathW,    (void**)&Orig_SHGetSpecialFolderPathW);
        HookExport(hShell32, NULL, "SHGetSpecialFolderPathA",    (void*)Hook_SHGetSpecialFolderPathA,    (void**)&Orig_SHGetSpecialFolderPathA);
    }

    HookExport(hKernelBase, hKernel32, "ExitProcess",           (void*)Hook_ExitProcess,           (void**)&Orig_ExitProcess);
    HookExport(hKernelBase, hKernel32, "DeviceIoControl",       (void*)Hook_DeviceIoControl,       (void**)&Orig_DeviceIoControl);
    HookExport(hKernelBase, hKernel32, "GetEnvironmentVariableW",(void*)Hook_GetEnvironmentVariableW,(void**)&Orig_GetEnvironmentVariableW);
    HookExport(hKernelBase, hKernel32, "GetEnvironmentVariableA",(void*)Hook_GetEnvironmentVariableA,(void**)&Orig_GetEnvironmentVariableA);
    HookExport(hKernelBase, hKernel32, "GetTempPathW",          (void*)Hook_GetTempPathW,          (void**)&Orig_GetTempPathW);
    HookExport(hKernelBase, hKernel32, "GetTempPathA",          (void*)Hook_GetTempPathA,          (void**)&Orig_GetTempPathA);
    HookExport(hKernelBase, hKernel32, "GetTempPath2W",         (void*)Hook_GetTempPath2W,         (void**)&Orig_GetTempPath2W);

    HookExport(hKernelBase, hKernel32, "CreateFileW",          (void*)Hook_CreateFileW,          (void**)&Orig_CreateFileW);
    HookExport(hKernelBase, hKernel32, "CreateFile2",          (void*)Hook_CreateFile2,          (void**)&Orig_CreateFile2);
    HookExport(hKernelBase, hKernel32, "CreateFileA",          (void*)Hook_CreateFileA,          (void**)&Orig_CreateFileA);
    HookExport(hKernelBase, hKernel32, "GetFileAttributesW",   (void*)Hook_GetFileAttributesW,   (void**)&Orig_GetFileAttributesW);
    HookExport(hKernelBase, hKernel32, "GetFileAttributesA",   (void*)Hook_GetFileAttributesA,   (void**)&Orig_GetFileAttributesA);
    HookExport(hKernelBase, hKernel32, "GetFileAttributesExW", (void*)Hook_GetFileAttributesExW, (void**)&Orig_GetFileAttributesExW);
    HookExport(hKernelBase, hKernel32, "FindFirstFileW",       (void*)Hook_FindFirstFileW,       (void**)&Orig_FindFirstFileW);
    HookExport(hKernelBase, hKernel32, "FindFirstFileA",       (void*)Hook_FindFirstFileA,       (void**)&Orig_FindFirstFileA);
    HookExport(hKernelBase, hKernel32, "FindFirstFileExW",     (void*)Hook_FindFirstFileExW,     (void**)&Orig_FindFirstFileExW);
    HookExport(hKernelBase, hKernel32, "CreateDirectoryW",     (void*)Hook_CreateDirectoryW,     (void**)&Orig_CreateDirectoryW);
    HookExport(hKernelBase, hKernel32, "CreateDirectoryA",     (void*)Hook_CreateDirectoryA,     (void**)&Orig_CreateDirectoryA);
    HookExport(hKernelBase, hKernel32, "DeleteFileW",          (void*)Hook_DeleteFileW,          (void**)&Orig_DeleteFileW);
    HookExport(hKernelBase, hKernel32, "DeleteFileA",          (void*)Hook_DeleteFileA,          (void**)&Orig_DeleteFileA);
    HookExport(hKernelBase, hKernel32, "RemoveDirectoryW",     (void*)Hook_RemoveDirectoryW,     (void**)&Orig_RemoveDirectoryW);
    HookExport(hKernelBase, hKernel32, "RemoveDirectoryA",     (void*)Hook_RemoveDirectoryA,     (void**)&Orig_RemoveDirectoryA);
    HookExport(hKernelBase, hKernel32, "MoveFileW",            (void*)Hook_MoveFileW,            (void**)&Orig_MoveFileW);
    HookExport(hKernelBase, hKernel32, "MoveFileExW",          (void*)Hook_MoveFileExW,          (void**)&Orig_MoveFileExW);
    HookExport(hKernelBase, hKernel32, "CopyFileW",            (void*)Hook_CopyFileW,            (void**)&Orig_CopyFileW);
    HookExport(hKernelBase, hKernel32, "CopyFileExW",          (void*)Hook_CopyFileExW,          (void**)&Orig_CopyFileExW);
    HookExport(hKernelBase, hKernel32, "ReplaceFileW",         (void*)Hook_ReplaceFileW,         (void**)&Orig_ReplaceFileW);
    HookExport(hKernelBase, hKernel32, "ReplaceFileA",         (void*)Hook_ReplaceFileA,         (void**)&Orig_ReplaceFileA);
}

void InitPortableEnvironment() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        g_NtQueryKey = (pfn_NtQueryKey)GetProcAddress(hNtdll, "NtQueryKey");
    }

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    g_appDir = exePath;

    
    std::wstring root = g_appDir;
    for (int i = 0; i < 4; i++) {
        std::wstring folder = ToUpper(PathFindFileNameW(root.c_str()));
        if (folder == L"WIN64" || folder == L"WIN32" || folder == L"X64" || folder == L"X86" ||
            folder == L"BIN" || folder == L"BINARIES" || folder == L"SHIPPING" || folder == L"RETAIL") {
            wchar_t parent[MAX_PATH];
            wcscpy_s(parent, root.c_str());
            PathRemoveFileSpecW(parent);
            if (wcslen(parent) >= 3 && _wcsicmp(parent, root.c_str()) != 0) {
                root = parent;
                continue;
            }
        }

        
        wchar_t checkEngine[MAX_PATH];
        PathCombineW(checkEngine, root.c_str(), L"..\\Engine");
        if (GetFileAttributesW(checkEngine) != INVALID_FILE_ATTRIBUTES) {
            wchar_t parent[MAX_PATH];
            wcscpy_s(parent, root.c_str());
            PathRemoveFileSpecW(parent);
            if (wcslen(parent) >= 3 && _wcsicmp(parent, root.c_str()) != 0) {
                root = parent;
                continue;
            }
        }
        break;
    }
    g_gameRootDir = root;

    g_overloadPathW = g_appDir + L"\\update";
    g_overloadPathA = WideToUtf8(g_overloadPathW);
    g_portableDir = g_appDir + L"\\PortableData";
    g_logFilePath = g_portableDir + L"\\portable_debug.log";
    g_regFilePath = g_portableDir + L"\\registry.ini";

    CreateDirectoryW(g_portableDir.c_str(), NULL);
    CreateDirectoryW((g_portableDir + L"\\Temp").c_str(), NULL);
    LoadConfig();

    auto ResolveKnownFolder = [](REFKNOWNFOLDERID rfid, int csidlFallback, std::wstring& outPath, const wchar_t* name) {
        PWSTR pPath = NULL;
        HRESULT hr = SHGetKnownFolderPath(rfid, 0, NULL, &pPath);
        if (SUCCEEDED(hr) && pPath) {
            outPath = NormalizeSlashes(pPath);
            CoTaskMemFree(pPath);
        } else {
            wchar_t fbBuf[MAX_PATH] = { 0 };
            if (SHGetFolderPathW(NULL, csidlFallback, NULL, SHGFP_TYPE_CURRENT, fbBuf) == S_OK) {
                outPath = NormalizeSlashes(fbBuf);
            } else {
                LogFormat(LOG_LVL_FAIL, L"[INIT ERROR] Failed to resolve system path for %s (HRESULT: 0x%08X)", name, hr);
            }
        }
    };

    ResolveKnownFolder(FOLDERID_RoamingAppData, CSIDL_APPDATA, g_realAppDataRoaming, L"AppData Roaming");
    ResolveKnownFolder(FOLDERID_LocalAppData, CSIDL_LOCAL_APPDATA, g_realAppDataLocal, L"AppData Local");
    ResolveKnownFolder(FOLDERID_LocalAppDataLow, CSIDL_APPDATA, g_realAppDataLocalLow, L"AppData LocalLow");
    ResolveKnownFolder(FOLDERID_Documents, CSIDL_MYDOCUMENTS, g_realDocuments, L"Documents");
    ResolveKnownFolder(FOLDERID_SavedGames, CSIDL_PROFILE, g_realSavedGames, L"Saved Games");
    ResolveKnownFolder(FOLDERID_ProgramData, CSIDL_COMMON_APPDATA, g_realProgramData, L"ProgramData");
    ResolveKnownFolder(FOLDERID_Profile, CSIDL_PROFILE, g_realUserProfile, L"UserProfile");
    ResolveKnownFolder(FOLDERID_PublicDocuments, CSIDL_COMMON_DOCUMENTS, g_realPublicDocuments, L"Public Documents");

    
    auto ResolveShortPath = [](const std::wstring& inLongPath) -> std::wstring {
        if (inLongPath.empty()) return L"";
        wchar_t shortBuf[MAX_PATH];
        DWORD sLen = GetShortPathNameW(inLongPath.c_str(), shortBuf, MAX_PATH);
        if (sLen > 0 && sLen < MAX_PATH) {
            return NormalizeSlashes(shortBuf);
        }
        return L"";
    };

    g_realAppDataRoamingShort   = ResolveShortPath(g_realAppDataRoaming);
    g_realAppDataLocalShort     = ResolveShortPath(g_realAppDataLocal);
    g_realAppDataLocalLowShort  = ResolveShortPath(g_realAppDataLocalLow);
    g_realDocumentsShort        = ResolveShortPath(g_realDocuments);
    g_realSavedGamesShort       = ResolveShortPath(g_realSavedGames);
    g_realProgramDataShort      = ResolveShortPath(g_realProgramData);
    g_realUserProfileShort      = ResolveShortPath(g_realUserProfile);
    g_realPublicDocumentsShort  = ResolveShortPath(g_realPublicDocuments);

    LoadRegistryFromIni();
}





BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hinstDLL);
            g_hSelfModule = (HMODULE)hinstDLL;

            
            g_pVehHandle = AddVectoredExceptionHandler(1, PortableVectoredHandler);
            SetUnhandledExceptionFilter(PortableCrashHandler);

            InitProxy();

            wchar_t exeName[MAX_PATH];
            GetModuleFileNameW(NULL, exeName, MAX_PATH);
            if (wcsstr(ToUpper(exeName).c_str(), L"UNITYCRASHHANDLER") != NULL) {
                return TRUE;
            }

            InitPortableEnvironment();

            
            
            if (!g_portableDir.empty()) {
                g_crashDumpDir = g_portableDir + L"\\CrashDumps";

                if (g_enableCrashDumps) {
                    CrashEnsureDirectoryTree(g_crashDumpDir.c_str());
                    g_crashDumpDirReady.store(true, std::memory_order_release);
                }

                LogFormat(
                    LOG_LVL_ALL,
                    L"[CRASH] Crash dumps enabled: %d, directory: \"%s\"",
                    (int)g_enableCrashDumps,
                    g_crashDumpDir.c_str()
                );
            }

			InstallAllHooks();
			InitNetworkSandbox();
            InstallEntryPointHook();
            break;
        }

        case DLL_PROCESS_DETACH:
            g_processExiting.store(true, std::memory_order_release);
            SafeSaveOnExit();
            break;
    }

    return TRUE;
}
