/* ---------------------------------------------------------------------
 * NetAdvanceStatistics
 * Copyright (C) 2020, NetAdvanceStatistics, Inc.  Unless you have an agreement
 * with NetAdvanceStatistics, Inc., for a separate license for this software code, the
 * following terms and conditions apply:
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License, Version 2.0.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero Public License for more details.
 *
 *
 * ----------------------------------------------------------------------
 */


 // Need to link with Iphlpapi.lib and Ws2_32.lib


#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS


#include <winsock2.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <stdio.h>
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>
#include "NetAdvanceStatistics.h"
#include <map> 

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))


int main(int argc, char* argv[])
{
    int ret = 0;
    if (argc < 2) {
        PrintUsage();
        return ret;
    }

    if ((argc == 2) && (strcmp(argv[1], "-all") == 0)) {
        ret = ShowTCPConnections();
        ret = ShowUDPConnections();
        return ret;
    }

    if ((argc == 2) && (strcmp(argv[1], "-tcp") == 0)) {
        ret = ShowTCPConnections();
        return ret;
    }

    if ((argc == 2) && (strcmp(argv[1], "-tcpstats") == 0)) {
        ret = ShowTCPStatistics();
        return ret;
    }

    if ((argc == 2) && (strcmp(argv[1], "-udp") == 0)) {
        ret = ShowUDPConnections();
        return 0;
    }

    if ((argc == 2) && (strcmp(argv[1], "-udpstats") == 0)) {
        ret = ShowUDPStatistics();
        return ret;
    }

    if ((argc >= 2) && (strcmp(argv[1], "-version") == 0)) {
        printf("NetAdvanceStatistics %s console", NET_PRODUCT_VER);
        return ret;
    }


    if ((argc >= 3) && (strcmp(argv[2], "-port") == 0)) {
        
        DWORD port = std::stoi(argv[3]);
        if (strcmp(argv[1], "-udp") == 0) {
            return ShowUDPConnections(port);
        } 
        if (strcmp(argv[1], "-tcp") == 0) {
            return ShowTCPConnections(port);
        }
        
        ShowUDPConnections(port);
        ShowTCPConnections(port);
        return 0;
    }


    if ((argc >= 3) && (strcmp(argv[2], "-portrange") == 0)) {
        std::vector<std::string> strs;
        
 
        if (std::string(argv[2]).find("-") == std::string::npos) {
            printf("Incorrect port range;\n");
            return 6;
        }

        boost::split(strs, argv[3], boost::is_any_of("-"));

        DWORD port = std::stoi(strs[0]);
        DWORD portSup = std::stoi(strs[1]);
 
        if (strcmp(argv[1], "-udp") == 0) {
            return ShowUDPConnections(port, portSup);
        }
        if (strcmp(argv[1], "-tcp") == 0) {
            return ShowTCPConnections(port, portSup);
        }

        ShowUDPConnections(port, portSup);
        ShowTCPConnections(port, portSup);
        return 0;
    }

    if ((argc >= 3) && (strcmp(argv[2], "-process") == 0)) {
        //TODO FILTER BY PROCESS
        
        size_t sizeInBytes = (strlen(argv[3]) * sizeof(CHAR)) + 1;
        CHAR* processToSearch = (CHAR*)malloc(sizeInBytes);
        strcpy_s(processToSearch, sizeInBytes, argv[3]);
       
        if (strcmp(argv[1], "-udp") == 0) {
            return ShowUDPConnections(processToSearch);
        }
        if (strcmp(argv[1], "-tcp") == 0) {
            return ShowTCPConnections(processToSearch);
        }

        ShowUDPConnections(processToSearch);
        ShowTCPConnections(processToSearch);

        free(processToSearch);
        return 0;
    }


  

    return 0;
}

int ShowUDPConnections(const CHAR* processNameToSearch) {
    return ShowUDPConnections(0, 0, processNameToSearch);
}

int ShowUDPConnections(DWORD port, DWORD portSup, const CHAR* processNameToSearch) {
    // Declare and initialize variables
    PMIB_UDPTABLE_OWNER_PID pUdpTable; // Pointer to the udptable
    DWORD dwSize = 0;
    BOOL bOrder = TRUE; // Ordenado
    ULONG ulAf = AF_INET; //iPv4
    UDP_TABLE_CLASS  tableClass = UDP_TABLE_OWNER_PID;

    DWORD dwRetVal = 0;
    char szLocalAddr[128];
    char szRemoteAddr[128];

    struct in_addr IpAddr;


    pUdpTable = (MIB_UDPTABLE_OWNER_PID*)MALLOC(sizeof(MIB_UDPTABLE_OWNER_PID));
    if (pUdpTable == NULL) {
        printf("Error allocating memory for pUdpTable\n");
        return 1;
    }

    // Make an initial call to GetExtendedTcpTable to
    // get the necessary size into the pdwSize variable
    dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, bOrder, ulAf, tableClass, 0);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pUdpTable);
        pUdpTable = (MIB_UDPTABLE_OWNER_PID*)MALLOC(dwSize);
        if (pUdpTable == NULL) {
            printf("Error allocating memory\n");
            return 2;
        }
    }


    // Make a second call to GetExtendedTcpTable to get
    // the actual data we require
    dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, bOrder, ulAf, tableClass, 0);
    if (dwRetVal == NO_ERROR) {

        printf(" Proto |    Local Addr:Local Port   |       PID    | Process Name\n");
        for (int i = 0; i < (int)pUdpTable->dwNumEntries; i++) {
            
            if (!isValidPort(port, portSup, pUdpTable->table[i].dwLocalPort)) {
                continue;
            }


            IpAddr.S_un.S_addr = (u_long)pUdpTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));

            CHAR* processName = nullptr;
            GetProcessByPid(pUdpTable->table[i].dwOwningPid, &processName);
            
            if (processNameToSearch != nullptr && processName != nullptr) {
                if (strcmp(processNameToSearch, processName) != 0) continue;
            }



           
       
            printf(" UDP %8s ", "");
            printf("%s:%d", szLocalAddr, ntohs((u_short)pUdpTable->table[i].dwLocalPort));

            size_t tInt = std::to_string(ntohs((u_short)pUdpTable->table[i].dwLocalPort)).length() + strlen(szLocalAddr) + 1;
            printf("%*s", (30 - tInt), "");

            printf("%i [ %s ]", pUdpTable->table[i].dwOwningPid, processName);
            printf("%5s\n", "");

            free(processName);
            


        }
    }
    else {
        printf("\pUdpTable failed with %d\n", dwRetVal);
        FREE(pUdpTable);
        return 3;
    }

    if (pUdpTable != NULL) {
        FREE(pUdpTable);
        pUdpTable = NULL;
    }

    return 0;
}


int ShowTCPConnections(const CHAR* processNameToSearch) {
    return ShowTCPConnections(0, 0, processNameToSearch);
}


int ShowTCPConnections(DWORD port, DWORD portSup, const CHAR* processNameToSearch) {
    // Declare and initialize variables
    PMIB_TCPTABLE_OWNER_PID pTcpTable; // Pointer to the tcptable
    DWORD dwSize = 0;
    BOOL bOrder = TRUE; // Ordenado
    ULONG ulAf = AF_INET; //iPv4
    TCP_TABLE_CLASS tableClass = TCP_TABLE_OWNER_PID_ALL;

    DWORD dwRetVal = 0;
    char szLocalAddr[128];
    char szRemoteAddr[128];

    struct in_addr IpAddr;


    pTcpTable = (MIB_TCPTABLE_OWNER_PID*)MALLOC(sizeof(MIB_TCPTABLE_OWNER_PID));
    if (pTcpTable == NULL) {
        printf("Error allocating memory for pTcpTable\n");
        return 1;
    }

    // Make an initial call to GetExtendedTcpTable to
    // get the necessary size into the pdwSize variable
    dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, bOrder, ulAf, tableClass, 0);
    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        FREE(pTcpTable);
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)MALLOC(dwSize);
        if (pTcpTable == NULL) {
            printf("Error allocating memory\n");
            return 2;
        }
    }


    // Make a second call to GetExtendedTcpTable to get
    // the actual data we require
    dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, bOrder, ulAf, tableClass, 0);
    if (dwRetVal == NO_ERROR) {
       
        printf(" Proto |  State      |    Local Addr:Local Port   |       Remote Addr: Remote Port  |   PID  [ Process Name ]\n");
        for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
            
            if (!isValidPort(port, portSup, pTcpTable->table[i].dwLocalPort)
                && !isValidPort(port, portSup, pTcpTable->table[i].dwRemotePort)) {
                continue;
            }

            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
            strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
            IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
            strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

            const CHAR* state;
            bool includeConnect = false;
            DWORD pSize = 0;
            CHAR* processName = nullptr;

            switch (pTcpTable->table[i].dwState) {

            case MIB_TCP_STATE_LISTEN:
                GetProcessByPid(pTcpTable->table[i].dwOwningPid, &processName);

                includeConnect = true;
                state = "LISTEN";
                break;

            case MIB_TCP_STATE_ESTAB:
                GetProcessByPid(pTcpTable->table[i].dwOwningPid, &processName);

                includeConnect = true;
                state = "ESTABLISHED";
                break;
            case MIB_TCP_STATE_TIME_WAIT:

                GetProcessByPid(pTcpTable->table[i].dwOwningPid, &processName);

                includeConnect = true;
                state = "TIME-WAIT";
                break;

            default:
                state = "";
                break;
            }

            if (processNameToSearch != nullptr && processName != nullptr) {
                if (strcmp(processNameToSearch, processName) != 0) continue;
            }

            if (includeConnect) {
                int n = (17 - strlen(state));
                printf(" TCP %5s %s ", "", state);
                printf("%*s", n, "");
                
                size_t tInt = std::to_string(ntohs((u_short)pTcpTable->table[i].dwLocalPort)).length() + strlen(szLocalAddr) + 1;
                printf("%s:%d",szLocalAddr, ntohs((u_short)pTcpTable->table[i].dwLocalPort));
                n = (30 - tInt);
                printf("%*s", n, "");

                tInt = std::to_string(ntohs((u_short)pTcpTable->table[i].dwRemotePort)).length() + strlen(szRemoteAddr) + 1;
                printf("%s:%d", szRemoteAddr, ntohs((u_short)pTcpTable->table[i].dwRemotePort));
                n = (30 - tInt);
                printf("%*s", n, "");

                printf("%i [ %s ]", pTcpTable->table[i].dwOwningPid, processName);
                printf("%5s\n", "");

             
                free(processName);
            }


        }
    }
    else {
        printf("\tGetTcpTable failed with %d\n", dwRetVal);
        FREE(pTcpTable);
        return 3;
    }

    if (pTcpTable != NULL) {
        FREE(pTcpTable);
        pTcpTable = NULL;
    }

    return 0;
}

int ShowTCPStatistics() {
    PMIB_TCPSTATS pTCPStats;
    DWORD dwRetVal = 0;

    pTCPStats = (MIB_TCPSTATS*)MALLOC(sizeof(MIB_TCPSTATS));
    if (pTCPStats == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    if ((dwRetVal = GetTcpStatistics(pTCPStats)) == NO_ERROR) {
        printf("\tActive Opens: %ld\n", pTCPStats->dwActiveOpens);
        printf("\tPassive Opens: %ld\n", pTCPStats->dwPassiveOpens);
        printf("\tSegments Recv: %ld\n", pTCPStats->dwInSegs);
        printf("\tSegments Xmit: %ld\n", pTCPStats->dwOutSegs);
        printf("\tTotal # Conxs: %ld\n", pTCPStats->dwNumConns);
    }
    else {
        printf("GetTcpStatistics failed with error: %ld\n", dwRetVal);

        LPVOID lpMsgBuf;
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            dwRetVal,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPTSTR)&lpMsgBuf,
            0,
            NULL)) {
            printf("\tError: %s", lpMsgBuf);
        }
        LocalFree(lpMsgBuf);
    }

    if (pTCPStats)
        FREE(pTCPStats);

    return 0;
}

int ShowUDPStatistics() {
    PMIB_UDPSTATS pUDPStats;
    DWORD dwRetVal = 0;

    pUDPStats = (MIB_UDPSTATS*)MALLOC(sizeof(MIB_UDPSTATS));
    if (pUDPStats == NULL) {
        printf("Error allocating memory\n");
        return 1;
    }

    if ((dwRetVal = GetUdpStatistics(pUDPStats)) == NO_ERROR) {
        printf("\tDatagrams received: %ld\n", pUDPStats->dwInDatagrams);
        printf("\tDatagrams discarded because of invalid port: %ld\n", pUDPStats->dwNoPorts);
        printf("\tDatagrams erroneous received: %ld\n", pUDPStats->dwInErrors);
        
        printf("\tDatagrams Xmit: %ld\n", pUDPStats->dwOutDatagrams); 
        printf("\tTotal # Conxs: %ld\n", pUDPStats->dwNumAddrs);
    }
    else {
        printf("GetUdpStatistics failed with error: %ld\n", dwRetVal);

        LPVOID lpMsgBuf;
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            dwRetVal,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
            (LPTSTR)&lpMsgBuf,
            0,
            NULL)) {
            printf("\tError: %s", lpMsgBuf);
        }
        LocalFree(lpMsgBuf);
    }

    if (pUDPStats)
        FREE(pUDPStats);

    return 0;
}

void PrintUsage() {

    printf(
        "  NetAdvanceStatistics (c) IJSP\n"
        "\n"
        "  Usage: NetAdvanceStatistics [key] [params (optional)] \n"
        "________________________________________________________________________________\n"
        "  Keys\n"
        "   -all                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT and UDP connections\n"
        "   -tcp                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT\n"
        "   -udp                         Enum all UDP connections \n"
        "   -tcpstats                    Show TCP Statistics on the current computer\n"
        "   -udpstats                    Show UDP Statistics on the current computer\n"
        "   -version                     Display NetAdvanceStatistics version\n"
        "  \nParams\n"
        "   -port                        Find port\n"
        "   -portrange                   Find in range. Ex: -portrange 8001-9001\n"
        "   -process                     Find connections used by the process. Ex: -process java.exe\n"
        "________________________________________________________________________________\n"
        "  Note: Currently IPv6 is not supported\n");

}

/*
    Pointer to pointer to modify the value of processName dinamically.
*/
int GetProcessByPid(DWORD pid, CHAR** processName) {

    TCHAR lpFileName[MAX_PATH] = L"Unknown";
    HMODULE hMod;
    DWORD cbNeeded;
    //u_short pid = ntohs((u_short)u_pid);
    
    HANDLE hdl = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
   

    if (hdl == NULL) {
       
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        // If the specified process is the System Process (0x00000000), the function fails and the last error code is ERROR_INVALID_PARAMETER. 
        // If the specified process is the Idle process or one of the CSRSS processes, this function fails and the last error code is ERROR_ACCESS_DENIED 
        // because their access restrictions prevent user-level code from opening them.
        wcscpy(lpFileName, enumAllProcesses(pid));

        *processName = (CHAR*)malloc(wcslen(lpFileName) + 1);
        int ret = wcstombs(*processName, lpFileName, wcslen(lpFileName) + 1);
        *(*processName + ret) = '\0';

    }
    else {
        if (EnumProcessModules(hdl, &hMod, sizeof(hMod), &cbNeeded))
        {
            GetModuleBaseName(hdl, hMod, lpFileName, sizeof(lpFileName) / sizeof(TCHAR));
        }
        *processName = (CHAR*)malloc(wcslen(lpFileName) + 1);

        int ret = wcstombs(*processName, lpFileName, wcslen(lpFileName) + 1);
        *(*processName + ret) = '\0';
        CloseHandle(hdl);
    }

    return 0;
}

BOOL isValidPort(DWORD& port, DWORD& portSup, DWORD& currentPortD) {
    u_short currentPort = ntohs((u_short)currentPortD);
	// All communications
	if (port == 0) {
		return TRUE;
	}


	// O find by port range Or find by port
	if (portSup != 0) {
		// by Port range
		if (currentPort >= port && currentPort <= portSup) {
			return TRUE;
		}
		return FALSE;
	}
	else {
        
		// by port
		if (port == currentPort) {
			return TRUE;
		}
		return FALSE;
	}


}


WCHAR* enumAllProcesses(DWORD pid) {

    HANDLE hndl = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hndl)
    {
        PROCESSENTRY32  process = { sizeof(PROCESSENTRY32) };
        Process32First(hndl, &process);
        do
        {
            if (process.th32ProcessID == pid) {
                CloseHandle(hndl);
                return process.szExeFile;
            }
        } while (Process32Next(hndl, &process));

        CloseHandle(hndl);
    }
}
