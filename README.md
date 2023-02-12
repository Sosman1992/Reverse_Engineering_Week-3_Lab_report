# Week 3 - Basic Dynamic Analysis

The Weeks Lab focus was on Basic Dynamic Analysis which involves running the malware to examine it behavior in a safe environment with tools including but not limited to Process Monitor, process Explorer, Wire Shark . Nontheless this analysis combines techniques used in both Basic static Analysis to help in providing certain clues about the sample before conducting the Basic Dynamic Analysis.

---
# Lab 3-1 

## Executive Summary

First of all Basic Static Analysis technique was conducted on the file sample named `Lab03-1.exe` which enabled in providing me initial information and clues about the sample. For Basic Static Analysis Steps followed was that I first of all uploaded the file Lab03.exe to Google's virusTotal.com, then went on to run the `strings` program on the sample to help me find clues as well as signatures if any that is associated with it, Moreover used PEid utility software to determine if the file `Lab03-1.exe` was packed and/or obfuscated, also opened the file in dependency walker and lastly used Resource hacker to ascertain whether the file lab-03.exe has hidden resources which may in addition get executed once the file Lab03-1.exe is launched. After performing the Basic static analysis which needs to be perfomed first, I then headed over to `hybrid-analysis.com` sandbox environment and uploaded the file `Lab03-1.exe`
Before conducting Basic Dynamic Analysis on the sample the following utility tools including but not limited to process monitor, process explorer, inetSim,ncat, wireshark needs to be launched. Then followed by double clicking the file `Lab03-1` to also get it executed in the isolated environment. Once the file begins executing it appears among the process listing in the process monitor utility software and clicking on it shows that the file creates a `WinVMX32` mutex and also `Ws2_32.dll` file is also present suggesting that the file possesses networking functions

## Indicators of Compromise 

**Compilation Date (presumed):**  JAN 2008

**MD5 Hash (EXE):** d537acb8f56a1ce206bc35cf8ff959c0

**SHA-1 Hash (EXE):**  0bb491f62b77df737801b9ab0fd14fa12d43d254

**SHA-256 Hash (EXE):** eb84360ca4e33b8bb60df47ab5ce962501ef3420bc7aab90655fd507d2ffcedd 

**File to look for:** vmx32to64.exe

**URL:** www.practicalmalwareanalysis.com

**File type:**  Win32 EXE  

**Mutex:** WinVMX32

## Mitigations

- Deletions of files matching any of these hashes obtained from the scanning result from the VirusTotal website
- Scan Windows machines for `system32\kerne132.dll`

## Evidence

Uploading the sample to Google virusTotal revealed that it was compiled on 06 january 2008 and it is a packed with a packer called PENinja; also Google virusTotal engine shows that it has an import function associated with it namely `ExitProcess`.

Running `strings` to help me in finding clues about the host-based and network based  signatures of the file. Going through the list of the  strings I found the web address `www.practicalmalwareanalysis.com` which is a network-based indicator and the string `vmx32to64.exe`which is a host-based indicator. 

Opening the file using PEid revealed that the file is packed using PEncrypt 3.1 Final which is something different from what virusTotal

using dependency walker to explore DLL dependencies and the imports of the file lab-03.exe showed `kernel32.dll` and`ntdll.dll` associated with it which had only one import namely `ExitProcess`
 
Lastly using Resource Hacker tool to check whether this file has certain resources associated with it; nonetheless no resource was showned.

---
# Lab 3-2

## Executive Summary
The sample appear to be malware, and it seems it will be running a service named `MalService` on the infected machine that would enable it in connecting to a website `www.malwareanalysis.com` to download other malwares to infect an affected computer system and people on its network.

## Indicators of Compromise

**Compilation Date :** SEPTEMBER 2010

**MD5 Hash (DLL):** 84882c9d43e23d63b82004fae74ebb61

**SHA-1 (DLL):** c6fb3b50d946bec6f391aefa4e54478cf8607211

**SHA-256 (EXE):** 5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9 

**URLs:** www.practicalmalwareanalysis.com

**File Type:** Win32 DLL  


## Mitigations
- Scanning through a computer system to see if is running a service called `MalService` then it implies the machine is infected

## Evidence

Opening the Lab file with PEiD, it can be seen that the file is packed with UPX a packing utililty. Using an unpacker it was able to unpack the file and get it to be recognized as Microsoft visual file that was written and compiled using Microsoft Visual C++ 6.0

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA` were revealed and they serve as a proof of the capability of the file connecting to the internet and in addition `CreateService` which is an import of the dynamic link library advapi32.dll serves as a proof that this suspected malware is capable of creating services on machines it infects to spread its infections.

Opening the unpacked`.EXE` using BinText GUI, suggests that infected machines will connect to `http://www.malwareanalysis.com` and in addition a running service named `MalService` for creating services that connects to the web and downloading of malwares  to infect the computer system and other machines on the network.

---

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- BinText: A sysinternals GUI program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports
- RegShot: for taking a snapshot before starting execution
- monitors the processes running on a system
- Process Monitor: Monitoring tool for Windows to monitor certain registry, file system, network, process, and thread activity.
- Process Explorer: Windows task manager that was run when performing dynamic analysis to help in provision of valuable insight into the processes      currently running on a system. You can use Process Explorer to list active processes, DLLs loaded by a process,various process properties, and overall system information. You can also use it to kill a process, log out users, and launch and validate processes.

Analyzing the malware provided for lab 3-1 through 3-3
using a combination of Basic Static Analysis and Basic 
Dynamic Analysis.

For Basic Static Analysis Steps followed:
 Uploading the file Lab03.exe to virusTotal.com
 Secondly run the `strings` program to help me find
 clues as well as signatures
 Next used PEid utility software to determine if the 
 file was packed 
 used dependency walker 
 and lastly used Resource hacker to evaluate the resource
 i found hidden the file lab-03.exe

For Basic Dynamic Analysis steps followed are:
 Basic static analysis needs to be perfomed first
 Uploading the file to a malware sandbox hybrid-analysis.com
 preparing for dynamic test by setting up enviroment
 with required tools to monitor the malware behavior
1. RegShot: for taking a snapshot before starting execution
2. Procmon: To clear log before starting
3. ProcessExplorer
4. ApateDNS: TO rEROUTE InetSim server 

lab 2
 



First of all uploading the sample to Google virusTotal
revealed that it was compiled on 06 january 2008 and
also showed that it is packed with a packer called PENinja
and also shows that it has an import function associated with it
namely `ExitProcess`. Next i run `strings` to help me in
finding clues about the host-based and network based 
signatures of the file. Going through the list of the 
strings I found the web address `www.practicalmalwareanalysis.com`
which is a network-based indicator and the string `vmx32to64.exe`
which is a host-based indicator. Opening the file using 
PEid revealed that the file is packed using PEncrypt 3.1 
Final which is something different from what virusTotal
using dependency walker to explore DLL dependencies and the 
imports of the file lab-03.exe showed `kernel32.dll` and
`ntdll.dll` associated with it which had only one import 
namely `ExitProcess`. and lastly using Resource Hacker tool
to check whether this file has certain resources associated
with it; nonetheless no resource was showned. 



lab 2
First of all uploading the sample to Google virusTotal
revealed that it was compiled on 06 january 2008 and
also showed that it is packed with a packer called Armadilo
and also shows that it has many import and export 
function associated with it. Next i run `strings` to help me in
finding clues about the host-based and network based 
signatures of the file. Going through the list of the 
strings I found the web address `www.practicalmalwareanalysis.com`
which is a network-based indicator and the string `vmx32to64.exe`
which is a host-based indicator. Opening the file using 
PEid revealed that the file is not packed and it was written and compiled using Microsoft Visual C++ 6.0
using dependency walker to explore DLL dependencies and the 
imports of the file lab-03.exe showed `kernel32.dll` and
`ntdll.dll` associated with it which had only one import 
namely `ExitProcess`. and lastly using Resource Hacker tool
to check whether this file has certain resources associated
with it; nonetheless no resource was showned.  
