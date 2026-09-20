#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>

extern int  g_logLevel;
extern bool g_enableNetwork;   
extern bool g_blockInternet;
extern bool g_logNetwork;
extern bool g_allowLocalhost;

void InitNetworkSandbox();
