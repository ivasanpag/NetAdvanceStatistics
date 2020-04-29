#pragma once


#define NET_COMPILE_VER		"1.0.0"
#define NET_PRODUCT_VER		"1.0"

int GetProcessByPid(DWORD pid, CHAR** processName);
void PrintUsage();

int ShowUDPConnections(const CHAR* processNameToSearch);
int ShowUDPConnections(DWORD port = 0, DWORD portSup = 0, const CHAR* processNameToSearch = nullptr);
int ShowUDPStatistics();

int ShowTCPConnections(const CHAR* processNameToSearch);
int ShowTCPConnections(DWORD port = 0, DWORD portSup = 0, const CHAR* processNameToSearch = nullptr);
int ShowTCPStatistics();
BOOL isValidPort(DWORD& port, DWORD& portSup, DWORD& currentPort);

WCHAR* enumAllProcesses(DWORD pid);
