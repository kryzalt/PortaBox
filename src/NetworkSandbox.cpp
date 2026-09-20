#define WIN32_LEAN_AND_MEAN
#include "NetworkSandbox.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <wininet.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")




extern bool CreateHook(void* targetFunc, void* hookFunc, void** originalTrampoline);
extern void LogFormat(int minLevel, const wchar_t* fmt, ...);
extern void LogRaw(const std::wstring& msg);
extern void HookExport(HMODULE hPrimary, HMODULE hSecondary, const char* funcName, void* hookFunc, void** origTrampoline);
extern int  g_logLevel;

#ifndef LOG_LVL_NET
#define LOG_LVL_NET 3
#endif




bool g_enableNetwork  = true;  
bool g_blockInternet  = false; 
bool g_logNetwork     = false; 
bool g_allowLocalhost = true;  






typedef int           (WSAAPI *pfn_connect)(SOCKET, const struct sockaddr*, int);
typedef int           (WSAAPI *pfn_WSAConnect)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int           (WSAAPI *pfn_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef struct hostent* (WSAAPI *pfn_gethostbyname)(const char*);
typedef int           (WSAAPI *pfn_getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int           (WSAAPI *pfn_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);

static pfn_connect        Orig_connect        = NULL;
static pfn_WSAConnect     Orig_WSAConnect     = NULL;
static pfn_sendto         Orig_sendto         = NULL;
static pfn_gethostbyname  Orig_gethostbyname  = NULL;
static pfn_getaddrinfo    Orig_getaddrinfo    = NULL;
static pfn_GetAddrInfoW   Orig_GetAddrInfoW   = NULL;


typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
static pfn_WinHttpSendRequest Orig_WinHttpSendRequest = NULL;


typedef HINTERNET (WINAPI *pfn_InternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *pfn_InternetOpenUrlW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *pfn_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *pfn_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *pfn_HttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *pfn_HttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *pfn_InternetGetConnectedState)(LPDWORD, DWORD);
typedef BOOL      (WINAPI *pfn_InternetCheckConnectionA)(LPCSTR, DWORD, DWORD);
typedef BOOL      (WINAPI *pfn_InternetCheckConnectionW)(LPCWSTR, DWORD, DWORD);

static pfn_InternetOpenUrlA         Orig_InternetOpenUrlA         = NULL;
static pfn_InternetOpenUrlW         Orig_InternetOpenUrlW         = NULL;
static pfn_InternetConnectA         Orig_InternetConnectA         = NULL;
static pfn_InternetConnectW         Orig_InternetConnectW         = NULL;
static pfn_HttpSendRequestA         Orig_HttpSendRequestA         = NULL;
static pfn_HttpSendRequestW         Orig_HttpSendRequestW         = NULL;
static pfn_InternetGetConnectedState Orig_InternetGetConnectedState = NULL;
static pfn_InternetCheckConnectionA  Orig_InternetCheckConnectionA  = NULL;
static pfn_InternetCheckConnectionW  Orig_InternetCheckConnectionW  = NULL;





static inline bool ShouldLogNetwork() {
    return g_logNetwork || (g_logLevel == LOG_LVL_NET);
}

static bool IsLocalAddress(const struct sockaddr* name) {
    if (!name) return false;
    if (name->sa_family == AF_INET) {
        sockaddr_in* addr4 = (sockaddr_in*)name;
        uint32_t ip = ntohl(addr4->sin_addr.s_addr);
        
        return ((ip >> 24) == 127) || (ip == 0);
    } else if (name->sa_family == AF_INET6) {
        sockaddr_in6* addr6 = (sockaddr_in6*)name;
        return memcmp(&addr6->sin6_addr, &in6addr_loopback, sizeof(in6_addr)) == 0;
    }
    return false;
}

static std::string SockAddrToString(const struct sockaddr* name) {
    if (!name) return "Unknown";
    char buf[INET6_ADDRSTRLEN] = { 0 };
    int port = 0;

    if (name->sa_family == AF_INET) {
        sockaddr_in* addr4 = (sockaddr_in*)name;
        inet_ntop(AF_INET, &addr4->sin_addr, buf, sizeof(buf));
        port = ntohs(addr4->sin_port);
    } else if (name->sa_family == AF_INET6) {
        sockaddr_in6* addr6 = (sockaddr_in6*)name;
        inet_ntop(AF_INET6, &addr6->sin6_addr, buf, sizeof(buf));
        port = ntohs(addr6->sin6_port);
    }

    std::ostringstream ss;
    ss << buf << ":" << port;
    return ss.str();
}






struct hostent* WSAAPI Hook_gethostbyname(const char* name) {
    std::string host = name ? name : "";
    bool isLocal = (host == "localhost" || host == "127.0.0.1");
    bool log = ShouldLogNetwork();

    if (log) {
        LogFormat(LOG_LVL_NET, L"[NET DNS (gethostbyname)] Host: \"%S\"", host.c_str());
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) {
            LogFormat(LOG_LVL_NET, L"[NET BLOCKED] Legacy DNS resolution for \"%S\" dropped", host.c_str());
        }
        WSASetLastError(WSAHOST_NOT_FOUND);
        return NULL;
    }

    return Orig_gethostbyname ? Orig_gethostbyname(name) : NULL;
}


int WSAAPI Hook_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
	std::string host = pNodeName ? pNodeName : "";
    std::string port = pServiceName ? pServiceName : "";
    
    bool isLocal = (host.empty() || host == "localhost" || host == "127.0.0.1" || host == "::1");
    bool log = ShouldLogNetwork();

    if (log) {
        LogFormat(LOG_LVL_NET, L"[NET DNS RESOLVE] Host: \"%S\", Port/Service: \"%S\"", host.c_str(), port.c_str());
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) {
            LogFormat(LOG_LVL_NET, L"[NET BLOCKED] DNS resolution for \"%S\" dropped", host.c_str());
        }
        return EAI_NONAME;
    }

    return Orig_getaddrinfo ? Orig_getaddrinfo(pNodeName, pServiceName, pHints, ppResult) : EAI_FAIL;
}

int WSAAPI Hook_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
	std::wstring host = pNodeName ? pNodeName : L"";
    std::wstring port = pServiceName ? pServiceName : L"";
    bool isLocal = (host.empty() || host == L"localhost" || host == L"127.0.0.1" || host == L"::1");
    bool log = ShouldLogNetwork();

    if (log) {
        LogFormat(LOG_LVL_NET, L"[NET DNS RESOLVE] Host: \"%s\", Port: \"%s\"", host.c_str(), port.c_str());
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) {
            LogFormat(LOG_LVL_NET, L"[NET BLOCKED] DNS resolution for \"%s\" dropped", host.c_str());
        }
        return EAI_NONAME;
    }

    return Orig_GetAddrInfoW ? Orig_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult) : EAI_FAIL;
}


int WSAAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    std::string endpoint = SockAddrToString(name);
    bool isLocal = IsLocalAddress(name);
    bool log = ShouldLogNetwork();

    if (log) {
        LogFormat(LOG_LVL_NET, L"[NET RAW CONNECT] TCP -> %S (Local: %d)", endpoint.c_str(), isLocal ? 1 : 0);
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) {
            LogFormat(LOG_LVL_NET, L"[NET BLOCKED] Outgoing TCP to %S was BLOCKED", endpoint.c_str());
        }
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    return Orig_connect ? Orig_connect(s, name, namelen) : SOCKET_ERROR;
}

int WSAAPI Hook_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    std::string endpoint = SockAddrToString(name);
    bool isLocal = IsLocalAddress(name);
    bool log = ShouldLogNetwork();

    if (log) {
        LogFormat(LOG_LVL_NET, L"[NET RAW WSACONNECT] TCP -> %S (Local: %d)", endpoint.c_str(), isLocal ? 1 : 0);
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) {
            LogFormat(LOG_LVL_NET, L"[NET BLOCKED] Outgoing WSAConnect to %S was BLOCKED", endpoint.c_str());
        }
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    return Orig_WSAConnect ? Orig_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS) : SOCKET_ERROR;
}


int WSAAPI Hook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
    if (to) {
        bool isLocal = IsLocalAddress(to);
        if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
            if (ShouldLogNetwork()) {
                std::string endpoint = SockAddrToString(to);
                LogFormat(LOG_LVL_NET, L"[NET BLOCKED] Outgoing UDP packet to %S (%d bytes) BLOCKED", endpoint.c_str(), len);
            }
            WSASetLastError(WSAEACCES);
            return SOCKET_ERROR;
        }
    }
    return Orig_sendto ? Orig_sendto(s, buf, len, flags, to, tolen) : SOCKET_ERROR;
}






HINTERNET WINAPI Hook_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    bool log = ShouldLogNetwork();
    if (log) {
        LogFormat(LOG_LVL_NET, L"[WININET URL] InternetOpenUrlA: %S", lpszUrl ? lpszUrl : "NULL");
    }

    if (g_blockInternet) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] InternetOpenUrlA blocked by policy");
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return NULL;
    }

    return Orig_InternetOpenUrlA ? Orig_InternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext) : NULL;
}

HINTERNET WINAPI Hook_InternetOpenUrlW(HINTERNET hInternet, LPCWSTR lpszUrl, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    bool log = ShouldLogNetwork();
    if (log) {
        LogFormat(LOG_LVL_NET, L"[WININET URL] InternetOpenUrlW: %s", lpszUrl ? lpszUrl : L"NULL");
    }

    if (g_blockInternet) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] InternetOpenUrlW blocked by policy");
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return NULL;
    }

    return Orig_InternetOpenUrlW ? Orig_InternetOpenUrlW(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext) : NULL;
}


HINTERNET WINAPI Hook_InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    bool log = ShouldLogNetwork();
    std::string srv = lpszServerName ? lpszServerName : "";
    bool isLocal = (srv == "localhost" || srv == "127.0.0.1");

    if (log) {
        LogFormat(LOG_LVL_NET, L"[WININET CONNECT] Host: %S, Port: %u", srv.c_str(), nServerPort);
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] InternetConnectA to %S blocked", srv.c_str());
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return NULL;
    }

    return Orig_InternetConnectA ? Orig_InternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext) : NULL;
}

HINTERNET WINAPI Hook_InternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    bool log = ShouldLogNetwork();
    std::wstring srv = lpszServerName ? lpszServerName : L"";
    bool isLocal = (srv == L"localhost" || srv == L"127.0.0.1");

    if (log) {
        LogFormat(LOG_LVL_NET, L"[WININET CONNECT] Host: %s, Port: %u", srv.c_str(), nServerPort);
    }

    if (g_blockInternet && (!isLocal || !g_allowLocalhost)) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] InternetConnectW to %s blocked", srv.c_str());
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return NULL;
    }

    return Orig_InternetConnectW ? Orig_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext) : NULL;
}


BOOL WINAPI Hook_InternetGetConnectedState(LPDWORD lpdwFlags, DWORD dwReserved) {
    if (g_blockInternet) {
        if (ShouldLogNetwork()) {
            LogFormat(LOG_LVL_NET, L"[WININET STATUS] Game checked InternetGetConnectedState -> Reported OFFLINE");
        }
        if (lpdwFlags) *lpdwFlags = 0;
        SetLastError(ERROR_NOT_CONNECTED);
        return FALSE; 
    }
    return Orig_InternetGetConnectedState ? Orig_InternetGetConnectedState(lpdwFlags, dwReserved) : FALSE;
}

BOOL WINAPI Hook_InternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    if (g_blockInternet) {
        if (ShouldLogNetwork()) LogFormat(LOG_LVL_NET, L"[WININET CHECK] InternetCheckConnectionA -> OFFLINE");
        SetLastError(ERROR_NOT_CONNECTED);
        return FALSE;
    }
    return Orig_InternetCheckConnectionA ? Orig_InternetCheckConnectionA(lpszUrl, dwFlags, dwReserved) : FALSE;
}

BOOL WINAPI Hook_InternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved) {
    if (g_blockInternet) {
        if (ShouldLogNetwork()) LogFormat(LOG_LVL_NET, L"[WININET CHECK] InternetCheckConnectionW -> OFFLINE");
        SetLastError(ERROR_NOT_CONNECTED);
        return FALSE;
    }
    return Orig_InternetCheckConnectionW ? Orig_InternetCheckConnectionW(lpszUrl, dwFlags, dwReserved) : FALSE;
}


BOOL WINAPI Hook_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    bool log = ShouldLogNetwork();
    if (log) {
        std::string body = "";
        if (lpOptional && dwOptionalLength > 0) {
            DWORD len = min(dwOptionalLength, (DWORD)512);
            body.assign((const char*)lpOptional, len);
        }
        LogFormat(LOG_LVL_NET, L"[HTTPS REQUEST] WinINet (HttpSendRequestA) Headers: %S | Payload (%u bytes): %S", 
            lpszHeaders ? lpszHeaders : "None", dwOptionalLength, body.c_str());
    }

    if (g_blockInternet) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] HttpSendRequestA blocked");
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }

    return Orig_HttpSendRequestA ? Orig_HttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength) : FALSE;
}

BOOL WINAPI Hook_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    bool log = ShouldLogNetwork();
    if (log) {
        std::string body = "";
        if (lpOptional && dwOptionalLength > 0) {
            DWORD len = min(dwOptionalLength, (DWORD)512);
            body.assign((const char*)lpOptional, len);
        }
        LogFormat(LOG_LVL_NET, L"[HTTPS REQUEST] WinINet (HttpSendRequestW) Headers: %s | Payload (%u bytes): %S", 
            lpszHeaders ? lpszHeaders : L"None", dwOptionalLength, body.c_str());
    }

    if (g_blockInternet) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] HttpSendRequestW blocked");
        SetLastError(ERROR_INTERNET_CANNOT_CONNECT);
        return FALSE;
    }

    return Orig_HttpSendRequestW ? Orig_HttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength) : FALSE;
}





BOOL WINAPI Hook_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    bool log = ShouldLogNetwork();
    if (log) {
        std::wstring headers = (lpszHeaders && dwHeadersLength != 0) ? 
            (dwHeadersLength == (DWORD)-1 ? lpszHeaders : std::wstring(lpszHeaders, dwHeadersLength)) : L"None";
        
        std::string bodyPreview = "";
        if (lpOptional && dwOptionalLength > 0) {
            DWORD len = min(dwOptionalLength, (DWORD)512);
            bodyPreview.assign((const char*)lpOptional, len);
        }

        LogFormat(LOG_LVL_NET, L"[HTTPS REQUEST] WinHttpSendRequest detected!");
        LogFormat(LOG_LVL_NET, L"  -> Headers: %s", headers.c_str());
        if (!bodyPreview.empty()) {
            LogFormat(LOG_LVL_NET, L"  -> Payload (%u bytes): %S%s", dwOptionalLength, bodyPreview.c_str(), dwOptionalLength > 512 ? "..." : "");
        }
    }

    if (g_blockInternet) {
        if (log) LogFormat(LOG_LVL_NET, L"[NET BLOCKED] WinHttpSendRequest blocked by policy");
        SetLastError(ERROR_WINHTTP_CANNOT_CONNECT);
        return FALSE;
    }

    return Orig_WinHttpSendRequest ? Orig_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext) : FALSE;
}





void InitNetworkSandbox() {
	if (!g_enableNetwork) {
        LogFormat(1, L"[NET INITIALIZED] Network sandbox is completely DISABLED by config.");
        return;
    }
    
    HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2_32) hWs2_32 = LoadLibraryW(L"ws2_32.dll");

    if (hWs2_32) {
        HookExport(hWs2_32, NULL, "gethostbyname", (void*)Hook_gethostbyname, (void**)&Orig_gethostbyname);
        HookExport(hWs2_32, NULL, "getaddrinfo",   (void*)Hook_getaddrinfo,   (void**)&Orig_getaddrinfo);
        HookExport(hWs2_32, NULL, "GetAddrInfoW",  (void*)Hook_GetAddrInfoW,  (void**)&Orig_GetAddrInfoW);
        HookExport(hWs2_32, NULL, "connect",       (void*)Hook_connect,       (void**)&Orig_connect);
        HookExport(hWs2_32, NULL, "WSAConnect",    (void*)Hook_WSAConnect,    (void**)&Orig_WSAConnect);
        HookExport(hWs2_32, NULL, "sendto",        (void*)Hook_sendto,        (void**)&Orig_sendto);
    }

    
    HMODULE hWinINet = GetModuleHandleW(L"wininet.dll");
    if (!hWinINet) hWinINet = LoadLibraryW(L"wininet.dll");

    if (hWinINet) {
        HookExport(hWinINet, NULL, "InternetOpenUrlA",          (void*)Hook_InternetOpenUrlA,          (void**)&Orig_InternetOpenUrlA);
        HookExport(hWinINet, NULL, "InternetOpenUrlW",          (void*)Hook_InternetOpenUrlW,          (void**)&Orig_InternetOpenUrlW);
        HookExport(hWinINet, NULL, "InternetConnectA",          (void*)Hook_InternetConnectA,          (void**)&Orig_InternetConnectA);
        HookExport(hWinINet, NULL, "InternetConnectW",          (void*)Hook_InternetConnectW,          (void**)&Orig_InternetConnectW);
        HookExport(hWinINet, NULL, "InternetGetConnectedState", (void*)Hook_InternetGetConnectedState, (void**)&Orig_InternetGetConnectedState);
        HookExport(hWinINet, NULL, "InternetCheckConnectionA",  (void*)Hook_InternetCheckConnectionA,  (void**)&Orig_InternetCheckConnectionA);
        HookExport(hWinINet, NULL, "InternetCheckConnectionW",  (void*)Hook_InternetCheckConnectionW,  (void**)&Orig_InternetCheckConnectionW);
        HookExport(hWinINet, NULL, "HttpSendRequestA",          (void*)Hook_HttpSendRequestA,          (void**)&Orig_HttpSendRequestA);
        HookExport(hWinINet, NULL, "HttpSendRequestW",          (void*)Hook_HttpSendRequestW,          (void**)&Orig_HttpSendRequestW);
    }

    
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryW(L"winhttp.dll");

    if (hWinHttp) {
        HookExport(hWinHttp, NULL, "WinHttpSendRequest", (void*)Hook_WinHttpSendRequest, (void**)&Orig_WinHttpSendRequest);
    }

    if (ShouldLogNetwork()) {
        LogFormat(LOG_LVL_NET, L"[NET INITIALIZED] Full Network Sandbox Active (Block=%d, AllowLocalhost=%d, LogLevel=%d)", 
            g_blockInternet ? 1 : 0, g_allowLocalhost ? 1 : 0, g_logLevel);
    }
}
