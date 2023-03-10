# Week 3 - Basic Dynamic Analysis

The Weeks Lab focus was on Basic Dynamic Analysis which involves running a suspected sample file to examine it behavior in a safe environment with tools including but not limited to Process Monitor, process Explorer, ncat, Wire Shark etc. Nontheless Dynamic analysis combines techniques used in both Basic static Analysis to help in providing certain clues about the sample before conducting the Basic Dynamic Analysis.

---
# Lab 3-1 

## Executive Summary

First of all Basic Static Analysis technique was conducted on the file sample named `Lab03-1.exe` which enabled in providing me initial information and clues about the sample. For Basic Static Analysis Steps followed are as follow; first of all, I uploaded the file `Lab03-1.exe` to Google's virusTotal.com website, then went on to run the `strings` program on the sample to help me find clues as well as signatures if any that may be associated with the suspected file, Moreover used PEid utility software to determine if the file `Lab03-1.exe` was packed and/or obfuscated, in addition, I also opened the file in dependency walker and lastly used Resource hacker to ascertain whether the file lab-03.exe has hidden resources which may in addition get executed once the file Lab03-1.exe is launched. After performing the Basic static analysis which needs to be perfomed first, I then headed over to `hybrid-analysis.com` sandbox environment and uploaded the file `Lab03-1.exe`  to enable in obtaining additional information about the file. Before conducting Basic Dynamic Analysis on the sample the following utility tools including but not limited to process monitor, process explorer, inetSim,ncat, wireshark needs to be launched, then followed by double clicking the file `Lab03-1` to also get it executed in the isolated environment. Once the file begins executing it appears among the process listing in the process monitor utility software and clicking on it shows that the file creates a `WinVMX32` mutex and also `Ws2_32.dll` file is also present suggesting that the file possesses networking functions

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

## Evidence

Uploading the sample to Google virusTotal revealed that it was compiled on 06 january 2008 and it is a packed with a packer called PENinja; also Google virusTotal engine shows that it has an import function associated with it namely `ExitProcess`.

Running `strings` to help me in finding clues about the host-based and network based  signatures of the file. Going through the list of the  strings I found the web address `www.practicalmalwareanalysis.com` which is a network-based indicator and the string `vmx32to64.exe`which is a host-based indicator. 

Opening the file using PEid revealed that the file is packed using PEncrypt 3.1 Final which is something different from what virusTotal

using dependency walker to explore DLL dependencies and the imports of the file lab-03.exe showed `kernel32.dll` and`ntdll.dll` associated with it which had only one import namely `ExitProcess`
 
Lastly using Resource Hacker tool to check whether this file has certain resources associated with it; nonetheless no resource was showned.

---
# Lab 3-2

## Executive Summary
First of all, I uploaded the `Lab03-2.DLL` file to Google's virusTotal.com website, then went on to run the `strings` program on the file to help me find clues as well as signatures if any that may be associated with the suspected file, Moreover used PEid utility software to determine if the file `Lab03-2.DLL` was packed and/or obfuscated. Moreover opening the `Lab03-2.DLL` in PEview revealed that this file five exports function assoociated with it including `install`,`installA`,`uninstallA` `ServiceMain` and `UninstallService`. In addition this DLL file is also composed of imported functions. In conclusion conducted Basic Dynamic Analysis on file using the available tools. With this DLL file I executed it using the command rundll32.exe, install A in the safe and controlled environment using my Virtual Box manager to monitor the file behavior whiles it is executed.

## Indicators of Compromise

**Compilation Date :** SEPTEMBER 2010

**MD5 Hash (DLL):** 84882c9d43e23d63b82004fae74ebb61

**SHA-1 (DLL):** c6fb3b50d946bec6f391aefa4e54478cf8607211

**SHA-256 (EXE):** 5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9 

**URLs:** www.practicalmalwareanalysis.com

**File Type:** Win32 DLL  


## Mitigations
- Scanning through a computer system process monitor to see if is running a service called svchost then it implies it gets the capabilty of installing services to infect machine it executes on.

## Evidence

Opening the Lab file with PEiD, it can be seen that the file is packed with UPX a packing utililty. Using an unpacker it was able to unpack the file and get it to be recognized as Microsoft visual file that was written and compiled using Microsoft Visual C++ 6.0

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA` were revealed and they serve as a proof of the capability of the file connecting to the internet and in addition `CreateService` which is an import of the dynamic link library advapi32.dll serves as a proof that this suspected malware is capable of creating services on machines it infects to spread its infections.

The export function "installA" of `LAB03-3.DLL` is used in installation of the suspected the malware as a Windows service and this was what caused the name of the sample to appear Windows Services Manager (services.msc) of process monitor, because when I running the other exports with the `rundll32.exe` no changes were shown in the registry

Using Regshot the DLL installed IPRIP with its value added to the standard registry in order to support a service called `svchost.exe` which is a process in windows used to hold running services

Typing `sc start `services.msc` at the command prompt started the malware service and allow it to execute.

---
# Lab 3-3

## Executive Summary
First and foremost, uploaded the `Lab03-3.EXE` file to Google's virusTotal.com website, then went on to run the `strings` program on the file to help me find clues as well as signatures if any that may be associated with the suspected file, Moreover used PEid utility software to determine if the file `Lab03-2.EXE` was packed and/or obfuscated. In conclusion conducted Basic Dynamic Analysis on file using the available tools.
## Indicators of Compromise

**Compilation Date :** SEPTEMBER 2010

**MD5 Hash (EXE):** 84882c9d43e23d63b82004fae74ebb61

**SHA-1 (EXE):** c6fb3b50d946bec6f391aefa4e54478cf8607211

**SHA-256 (EXE):** 5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9 

**URLs:** www.practicalmalwareanalysis.log

**File Type:** Win32 EXE 


## Mitigations
- Scanning through a computer system to see if is running a service in the string properties of process monitor called `svchost` that replaced the file name Lab03-3

## Evidence
Opening the file using PE view there is no indication of the file packed looking at the virtual and raw size of the file. Also looking at .rdata section of the file it can be seen that there are ton of imports function from kernel32.dll that performs process manipulation, file creation and memory manipulation

Opening file explorer and double clicking the file in the safe environment it can be seen that the svchost.exe memory section has a bunch of key strings stored in it memory that are associated keyboard functionality. 

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, that this suspected malware is capable of creating services on machines it infects to capture keystrokes.

Double clicking lab 03-3 in the safe environment setup, Lab03-3.exe popped up in the process listing and then `svchost.exe`(which is a process in windows used to hold running service) popped below it and then lab03-3 disappeared

---

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- BinText: A sysinternals GUI program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports
- RegShot: for taking a snapshot before starting execution
- monitors the processes running on a system
- Process Monitor: Monitoring tool for Windows to monitor certain registry, file system, network, process, and thread activity of a malware's behavior
- Process Explorer: Windows task manager that was run when performing dynamic analysis to help in provision of valuable insight into the processes currently running on a system. Process Explorer lists active processes, DLLs loaded by a process,various process properties, and overall system information. Process Explorer can also be used to kill a process, log out users, and launch and validate processes.
- InetSim: InetSim was used to simulate various network services and protocols that are commonly used by malware, such as HTTP, DNS, and SMTP to serve as a fake internet connection

