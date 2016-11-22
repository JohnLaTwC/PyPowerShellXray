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
         [Byte[]]$z = 0xb8,0x46,0x0f,0x64...REST OF SHELLCODE;
         ...
         $Nb7=$w::VirtualAlloc(0,0x1000,$g,0x40);
         ...
         $w::CreateThread(0,0,$Nb7,0,0,0);

     With the shellcode it tries:
     - Resolve APIs. The APIs used by shellcode gives defenders a clue as to what to look for on host.
         e.g. if you calls to winsock/wininet/winhttp APIs, you know they connected to a URL or IP
         e.g. if you see a call to WinExec / CreateProcess, you know something was downloaded and spawned
         push 0x0726774c         << 0x0726774c is the hash of the API text "kernel32.dll!LoadLibraryA"
         call ebp --> kernel32.dll!LoadLibraryA
         pretty sure @stephenfewer came up with blockhash in https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
         Rather than have a hardcoded list of API hashes, it build a dictionary based on your local binaries. 
         This means the script requires Windows as the underlying OS to do this.
         
     - Display ascii text for DWORD constants to assist decoding. 
         e.g. the below shows the encoding of ws2_32 [.dll] before a call to LoadLibrary
         push 0x00003233--> '23'
         push 0x5f327377--> '_2sw'
         push esp
         push 0x0726774c--> '&wL' << garbage. this is just the API hash for 'kernel32.dll!LoadLibraryA'
         call ebp --> kernel32.dll!LoadLibraryA
     - Display IP:port for calls to socket/Internet APIs
         push 0x68bff1c0
         push 0xbb010002--> IP 192.241.191.104:443
     - Display a hex dump to look for strings
     - Decode some encoded shellcode. Shellcode is often encoded.  A common one is shikata_ga_nai.
         You can disable this behavior by the -nx switch
         Here is an example of the shikata encoder in action:
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

         Post decode you get something like:
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
     A real programmer would use an emulator (libemu).  Not this script

