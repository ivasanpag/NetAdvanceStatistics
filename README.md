# NetAdvanceStatistics

Windows Utility to find TCP or UDP ports in use in your current machine

Usage: NetAdvanceStatistics [key] [params (optional)]

- Keys
-all                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT and UDP connections
-tcp                         Enum all TCP connections ESTABLISHED, LISTEN OR TIME-WAIT
-udp                         Enum all UDP connections 
-tcpstats                    Show TCP Statistics on the current computer
-udpstats                    Show UDP Statistics on the current computer
-version                     Display NetAdvanceStatistics version
- Params
-port                        Find port
-portrange                   Find in range. Ex: -portrange 8001-9001
-process                     Find connections used by the process. Ex: -process java.exe

> **Note:** Currently IPv6 is not supported

 **Examples**
 NetAdvanceStatistics.exe -tcp -port 8080
 NetAdvanceStatistics.exe -all -portrange 80-443
  NetAdvanceStatistics.exe -tcp -process java.exe

# Compilation
Compiled in Visual Studio 2019
