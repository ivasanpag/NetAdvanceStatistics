# NetAdvanceStatistics

Windows Utility to find TCP or UDP ports in use in your current machine

Usage: NetAdvanceStatistics [key] [params (optional)]<br />

- Keys<br />
-all                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT and UDP connections<br />
-tcp                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT<br />
-udp                         Enum all UDP connections <br />
-tcpstats                    Show TCP Statistics on the current computer<br />
-udpstats                    Show UDP Statistics on the current computer<br />
-version                     Display NetAdvanceStatistics version<br />
- Params<br />
-port                        Find port<br />
-portrange                   Find in range. Ex: -portrange 8001-9001<br />
-process                     Find connections used by the process. Ex: -process java.exe<br />

> **Note:** Currently IPv6 is not supported

 **Examples**
 NetAdvanceStatistics.exe -tcp -port 8080 <br />
 NetAdvanceStatistics.exe -all -portrange 80-443 <br />
 NetAdvanceStatistics.exe -tcp -process java.exe <br />

# Compilation
Compiled in Visual Studio 2019
