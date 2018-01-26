## Even more hacked together by @JohnLaTwC, Jan 2018
## v 0.9, Jan 2018, fix various broken decode bugs
## v 0.8, Sept 2017, add support for stored DB paths to enable shellcode API resolution when run on mac/linux
## v 0.7, Dec 2016, decode B64 snippets
## v 0.6, Nov 2016

## With apologies to @Lee_Holmes for using Python instead of PowerShell. In decoding so much PowerShell, I didn't want to risk a self-infection :)
## 
## This script attempts to decode encoded powershell commands.  
##   REQUIREMENTS: This script uses vivisect for PE parsing and dissasembly: https://github.com/vivisect/vivisect. Set the PYTHONPATH as appropriate.
## e.g. set pythonpath=C:\vivisect-master\vivisect-master

## Things this script tries to do.  Emphasis on tries.
## * It attempts to decode recusively if instructed (via the -r switch)
## * It attempts to find Base64 data, compressed content (Gzip, Deflate), or char[]](77,105,95) style encoding
## * It attempts to 'find/replace' the encoded text in the powershell command. This is handy
##      if the script has numerous chunks of encoded content
## * If it finds shellcode, it attempts to display it. LIMITATION: x86 shellcode only
##      If you ever come across this sequence in PowerShell, you know you have shellcode
##          [Byte[]]$z = 0xb8,0x46,0x0f,0x64...REST OF SHELLCODE;
##          ...
##          $Nb7=$w::VirtualAlloc(0,0x1000,$g,0x40);
##          ...
##          $w::CreateThread(0,0,$Nb7,0,0,0);
## 
##      With the shellcode it tries:
##      - Resolve APIs. The APIs used by shellcode gives defenders a clue as to what to look for on host.
##          e.g. if you calls to winsock/wininet/winhttp APIs, you know they connected to a URL or IP
##          e.g. if you see a call to WinExec / CreateProcess, you know something was downloaded and spawned
##          push 0x0726774c         << 0x0726774c is the hash of the API text "kernel32.dll!LoadLibraryA"
##          call ebp --> kernel32.dll!LoadLibraryA
##          pretty sure @stephenfewer came up with blockhash in https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/block/block_api.asm
##          Rather than have a hardcoded list of API hashes, it build a dictionary based on your local binaries. 
##          This means the script requires Windows as the underlying OS to do this.
##          
##      - Display ascii text for DWORD constants to assist decoding. 
##          e.g. the below shows the encoding of ws2_32 [.dll] before a call to LoadLibrary
##          push 0x00003233--> '23'
##          push 0x5f327377--> '_2sw'
##          push esp
##          push 0x0726774c--> '&wL' << garbage. this is just the API hash for 'kernel32.dll!LoadLibraryA'
##          call ebp --> kernel32.dll!LoadLibraryA
##      - Display IP:port for calls to socket/Internet APIs
##          push 0x68bff1c0
##          push 0xbb010002--> IP 192.241.191.104:443
##      - Display a hex dump to look for strings
##      - Decode some encoded shellcode. Shellcode is often encoded.  A common one is shikata_ga_nai.
##          You can disable this behavior by the -nx switch
##          Here is an example of the shikata encoder in action:
##          0x00000000 b8460f64cf       mov eax,0xcf640f46          << 4byte XOR key
##          0x00000005 dbcf             fcmovne st0,st7             << execute any floating point operation to set up GetPC
##          0x00000007 d97424f4         fnstenv  [esp - 12]         << stores floating point state
##          0x0000000b 5d               pop ebp                     << GetPC: pop addr of last FP instr into ebp
##          0x0000000c 29c9             sub ecx,ecx
##          0x0000000e b147             mov cl,71                   << 71 DWORD to decode
##          0x00000010 314513           xor dword [ebp + 19],eax    << start of XOR decode loop
##          0x00000013 83edfc           sub ebp,0xfffffffc          << increment counter by 4 
##          0x00000016 034549           add eax,dword [ebp + 73]    << partial garbage instruction
##          0x00000019 ed               in eax,dx                   << garbage b/c it's encoded
##          0x0000001a 91               ... garbarge bytes continue
##
##          Post decode you get something like:
##          0x00000010 314513           xor dword [ebp + 19],eax
##          0x00000013 83edfc           sub ebp,0xfffffffc
##          0x00000016 03450f           add eax,dword [ebp + 15] << pre decode this was: add eax,dword [ebp + 73] 
##          0x00000019 e2f5             loop 0x00000010             << the expected loop operation. 71 times
##          0x0000001b fc               cld                         ... decoded content. it's now valid shellcode
##          0x0000001c e882000000       call 0x000000a3
##          0x00000021 60               pushad 
##          0x00000022 89e5             mov ebp,esp
##          0x00000024 31c0             xor eax,eax
##          0x00000026 648b5030         fs: mov edx,dword [eax + 48]
##          0x0000002a 8b520c           mov edx,dword [edx + 12]
##          0x0000002d 8b5214           mov edx,dword [edx + 20]
##          0x00000030 8b7228           mov esi,dword [edx + 40]
##          0x00000033 0fb74a26         movzx ecx,word [edx + 38]
##          ...
##      A real programmer would use an emulator (libemu).  Not this script


import sys
import zlib
import re
import argparse
import string
from envi.archs.i386 import i386Disasm 

szDbPath = None
fDbLoaded = False
fVerbose = False
APIDict = {}
fDecodeShellcode = True
dis = i386Disasm()

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def hashapi(sz):
    val = 0
    for a in sz:
        val = ror(val, 0xd, 32)
        val = val + ord(a)
    return val

def blockhash(szDll, szAPI):
    from array import array
    sz = unicode(szDll.upper() + '\0')
    szEncDll = sz.encode("utf-16")
    szEncAPI = szAPI.encode("ascii") + '\0'
    
    iDll = hashapi(szEncDll[2:])
    iAPI = hashapi(szEncAPI)
    return 0x0000FFFFFFFF & (iDll+iAPI)


## This function makes the script Windows specific. It expect Windows binaries and uses them
## to build up a dictionary of API hashes.  One could fix this by doing this step on a 
## Windows PC and then storing the API hashes in file
## Sept 2017: support the ability to load from a DB
def PopulateExports(APIDict, szDll):
    global fVerbose
    from PE import PE
    import os
    fd = open(os.environ['SYSTEMROOT']+ '\\System32\\' +  szDll, 'rb')
    pe = PE(fd)
    for exp in pe.getExports():
        szAPI = exp[2]
        szHash = "0x%08x"%(blockhash(szDll, szAPI))
        APIDict[szHash] =  szDll + "!" + szAPI
        if (fVerbose):
            print("INSERT INTO APIs (module, api,hashvalue) VALUES('%s','%s','%s')" % (szDll, szAPI, szHash))

##  example:
##  0x00000000 b9c7060000       mov ecx,1735
##  0x00000005 e8ffffffff       call 0x00000009
##  0x0000000a c15e304c         rcr dword [esi + 48],76
##  0x0000000e 0e               push cs
##  0x0000000f 07               pop es
##  0x00000010 e2fa             loop 0x0000000c
##  0x00000012 b8b7050405       mov eax,0x050405b7
def decode_call_to_self(d, all_instr_list):
    ## verify some bytes first
    import array
    sd = array.array('B', d)
    szd = None

    #look for mov and call to self after a min number of instructions
    if len(all_instr_list) < 10:
        return None

    fFoundMov = False
    fFoundCounter = False
    fFoundCallToSelf = False
    iLen = 0
    iCallOffset = 0
    szMsg = 'No decoder found'
    for i in range(0, 2):
        instr_lst = all_instr_list[i]
        szInsBytes = instr_lst[1]
        szIns = instr_lst[2]
        offset = instr_lst[3]
        # e8ffffffff       call 0x00000009
        if szInsBytes == "e8ffffffff":
            fFoundCallToSelf = True
            iCallOffset = offset + 5
        # mov ecx,1735
        if szIns.startswith('mov ') and szIns.find('ecx,') > 0:
            fFoundCounter = True
            iLen = int(szIns.split(',')[1])
    if (fFoundCallToSelf and fFoundCounter and iLen > 0):
        szMsg = "Found call_to_self shellcode len = %d, decode offset= %d" % (iLen, iCallOffset)
        szd = []
        for i in range(0,iCallOffset):
            szd.append(chr(sd[i]))
        szd.append(chr(sd[iCallOffset - 1]))
        for i in range(iCallOffset,len(sd)-iCallOffset):
            szd.append(chr(sd[i]))
        return [''.join(szd), iLen, 0, iCallOffset, szMsg]

    return [None, 0, 0, 0, szMsg]

##  Example shellcode
##  0x00000000 dbd3             fcmovnbe st0,st3 
##  0x00000002 be1dd3f6b2       mov esi,0xb2f6d31d 
##  0x00000007 d97424f4         fnstenv  [esp - 12] 
##  0x0000000b 5a               pop edx 
##  0x0000000c 33c9             xor ecx,ecx 
##  0x0000000e b16e             mov cl,110 
##  0x00000010 83c204           add edx,4 
##  0x00000013 317214           xor dword [edx + 20],esi 
##  0x00000016 037209           add esi,dword [edx + 9] 
def decode_shikata_ga_nai(d, all_instr_list):
    ## verify some bytes first
    import array
    sd = array.array('B', d)
    szd = None

    #look for floating point instr, fnstenv, and mov in first few instr
    if len(all_instr_list) < 10:
        return None

    fFoundFnstenv = False
    fFoundFloatingPtInstr = False
    fFoundMov = False
    fFoundCounter = False
    fFoundXor = False
    iLen = 0
    key = 0
    szMsg = 'No decoder found'
    iXorOffset = 0
    iXorAdjust = 0
    iFPOpOffset = 0
    for i in range(0, 10):
        instr_lst = all_instr_list[i]
        szIns = instr_lst[2]
        offset = instr_lst[3]
        # fnstenv  [esp - 12] 
        if szIns.startswith('fnstenv'):
            fFoundFnstenv = True
        #fxch st0,st6 
        if not fFoundFloatingPtInstr and not szIns.startswith('fnstenv') and szIns.startswith('f'):
            fFoundFloatingPtInstr = True
            iFPOpOffset = offset
        #xor dword [edx + 24],eax 
        if szIns.startswith('sub ') and szIns.endswith('0xfffffffc'):
            iXorAdjust = -4
        if szIns.startswith('xor dword ['):
            fFoundXor = True
            iXorOffset = int((szIns.split('+')[1]).split(']')[0]) ##+ iXorAdjust 
            #find key operation. e.g. add esi,dword [eax + 14]
            for j in range(1,3):
                keyop_instr_lst = all_instr_list[i+j]
                szKeyOpIns = keyop_instr_lst[2]
                if szKeyOpIns.startswith('add e'):
                    szKeyOp = szKeyOpIns.split(' ')[0]
                    istart = keyop_instr_lst[3]
                    break
        # mov eax,0x4193fabc 
        if szIns.startswith('mov ') and szIns.find('0x') > 0 and not fFoundMov:
            fFoundMov = True
            k1 = sd[offset + 0x1]
            k2 = sd[offset + 0x2]
            k3 = sd[offset + 0x3]
            k4 = sd[offset + 0x4]
            key = k1 | (k2 << 8) | (k3 << 16)| (k4 << 24)
        # mov cl,110
        if szIns.startswith('mov ') and szIns.find('cl,') > 0:
            fFoundCounter = True
            iLen = int(szIns.split(',')[1])
    if (fFoundMov and fFoundFloatingPtInstr and fFoundFnstenv and fFoundCounter and iLen > 0):

        next_key_operation = d[istart: istart+3]
        
        szd = []
        for i in range(0,iXorOffset + iFPOpOffset):
            szd.append(chr(sd[i]))

        for i in range(iXorOffset + iFPOpOffset,len(sd)-(iXorOffset + iFPOpOffset), 4):
            szd.append(chr(k1 ^ sd[i]))
            szd.append(chr(k2 ^ sd[i+1]))
            szd.append(chr(k3 ^ sd[i+2]))
            szd.append(chr(k4 ^ sd[i+3]))
            data = k1^sd[i] | ((k2^sd[i+1]) << 8) | ((k3^sd[i+2]) << 16) | ((k4^sd[i+3]) << 24)

            #update the key based on the shikata rules
            if szKeyOp == "add":
                key = (key + data) & 0x00000000FFFFFFFF
            else:
                key = (key + data) & 0x00000000FFFFFFFF
                pass # error case

            k1 = 0x000000FF & key
            k2 = (0x0000FF00 & key) >> 8
            k3 = (0x00FF0000 & key) >> 16
            k4 = (0xFF000000 & key) >> 24

        szd = ''.join(szd)

        op = dis.disasm(szd, istart, istart)
        szIns = repr(op).lower()
        szKeyOp = szIns.split(' ')[0]
        # szOffsetDirection = szIns.split(' ')[3]
        # cOffset = int((szIns.split(' ')[4]).split(']')[0])
        szMsg = "Found shikata_ga_nai shellcode len = %d, key = 0x%x, decode offset= %d, fpop offset = %d, keyop= %s, istart=0x%x, '%s'" % (iLen, key, iXorOffset, iFPOpOffset, szKeyOp, istart, szIns)
    else:
        pass
    return [szd, iLen, key, iXorOffset, szMsg]

def process_instructions_impl(d, offset, va):
    global dis
    instr_list = []
    all_instr_list = []
    final_offset_msg= ''
    while offset < len(d):
        op = None
        try:
            op = dis.disasm(d, offset, va+offset)
            szIns = repr(op).lower()
            instr_lst = ['0x%.8x' % (va+offset),
                         '%s' % str(d[offset:offset+len(op)].encode('hex')),
                         szIns,
                         offset ]
            all_instr_list.append(instr_lst)
            offset += len(op)
        except Exception as e1: 
            final_offset_msg = 'Decode error at offset 0x%x' % offset
            break
    return [all_instr_list, final_offset_msg]

def process_instructions(d):
    return process_instructions_impl(d,0,0)

def prepareAPIs():
    global APIDict
    global szDbPath
    global fDbLoaded

    ## if APIs are being loaded from a DB, then do that now
    if (szDbPath is not None and not fDbLoaded):
        import sqlite3
        db = sqlite3.connect(szDbPath)
        cursor = db.cursor()
        cursor.execute('''SELECT module, api, hashvalue FROM APIs''')
        all_rows = cursor.fetchall()
        for row in all_rows:
            szHash = row[2]
            szDll = row[0]
            szAPI = row[1]
            APIDict[szHash] =  szDll + "!" + szAPI
        db.close()
        fDbLoaded = True
    else:
        PopulateExports(APIDict, 'kernel32.dll')
        PopulateExports(APIDict, 'ws2_32.dll')
        PopulateExports(APIDict, 'ole32.dll')
        PopulateExports(APIDict, 'ntdll.dll')
        PopulateExports(APIDict, 'advapi32.dll')
        PopulateExports(APIDict, 'urlmon.dll')
        PopulateExports(APIDict, 'winhttp.dll')
        PopulateExports(APIDict, 'wininet.dll')

def dumpShellcode(d):
    global fDecodeShellcode
    global APIDict
    szOut = ''
    if len(APIDict) == 0:
        prepareAPIs()
        ## for szKey in APIDict.keys():
        ##      print ("%s  %s" % (szKey, APIDict[szKey]))

    # set pythonpath=<path to to>\vivisect
    szIns = szPrev = ''
    instr_list = []

    outputparamlst = process_instructions(d)
    all_instr_list = outputparamlst[0]
    final_offset_msg = outputparamlst[1]

    if fDecodeShellcode:
        decoder_funcs = [decode_shikata_ga_nai, decode_call_to_self]
        try:
            for decoder_func in decoder_funcs:
                out_params = decoder_func(d, all_instr_list)
                if out_params is not None and out_params[0] is not None:
                    szd = out_params[0]
                    iLen = out_params[1]
                    key = out_params[2]
                    iXorOffset = out_params[3]
                    szMsg = out_params[4]
                    szOut += szMsg + '\n'

                    outputparamlst = process_instructions(szd)
                    all_instr_list = outputparamlst[0]
                    final_offset_msg = outputparamlst[1]
                    d = szd

        except Exception as e1:
            print(e1)

    # display hex dump
    szdisplay = ' '.join([hex(ord(c))[2:].zfill(2) for c in d])
    print('Hex dump: ' + szdisplay)

    for i in range(0, len(all_instr_list)):
        instr_lst = all_instr_list[i]
        szIns = instr_lst[2]
        szOut += '%s %s %s' % (instr_lst[0], instr_lst[1].ljust(16), szIns)
        if (i > 0):
            szPrev = all_instr_list[i-1][2]

        if (szIns == 'call ebp'):
            szDword = None
            if (szPrev.find("push 0x") >= 0 or re.search("mov e\wx,0x",szPrev) >= 0):
                szDword = szPrev[-10:]
            if (i > 2 and all_instr_list[i-1][1] == "0000" and all_instr_list[i-2][1] == "0000"):
                szDword = all_instr_list[i-3][2][-10:]
            if szDword is not None:
                if szDword in APIDict.keys():
                    szOut +=  " --> " + APIDict[szDword] + '\n';
                else:
                    szOut += '\n'
            else:
                szOut += '\n'
        elif (szIns.find('push 0x') >= 0 and szIns.find('0002')>0 and szPrev.find('push 0x') >= 0 ):
            #decode addr and port
            #0x000000ad 683418905b       push 0x5b901834 IP
            #0x000000b2 68020001bb       push 0xbb010002 port in highword
            szPort = szIns.split(' ')[1][2:6]
            szIP = szPrev.split(' ')[1]
            hexIP = int(szIP, 16)
            hexPort = int(szPort, 16)  
            hexPort = ((hexPort & 0x0000FF00) >> 8)  + ((hexPort & 0x000000FF) << 8) 
            szOut += "--> IP %s.%s.%s.%s:%s\n" % (hexIP & 0x000000FF, (hexIP & 0x0000FF00) >> 8, (hexIP & 0x00FF0000)>>16, (hexIP & 0xFF000000) >> 24 , hexPort)
        elif (szIns.find('push 0x') >= 0 or (szIns.find('mov ') >= 0 and szIns.find(',0x') > 0)):
            szDword = szIns.split('0x')[1] # push 0x00707474  --> 007907474
            ## if dword is displayable characters (or NUL) then concatenate into a string
            szdw = ''.join([chr(int(''.join(c), 16)) for c in zip(szDword[0::2],szDword[1::2])])
            szbytes = ''.join(map(lambda c: c if c in string.printable else '', szdw))
            szbytes = szbytes.replace('\r',' ').replace('\n','')
            if len(szbytes) >= 2:
                szOut += "--> '" + szbytes + "'\n"
            else:
                szOut += '\n'
        else:
            szOut += '\n'
        szPrev = szIns
    
    szOut+= '\nByte Dump:\n'
    i = 0
    sz = ''
    for b in d:
        i+=1
        if (b in string.printable):
            sz += b.encode('utf-8').strip()
        else:
            sz +='.'
    
    sz = sz.replace(' ','')
    szOut += sz
    return szOut

def xray(sz0):
    global fVerbose
    out = ''
    #first transform any char[](dec, dec) strings:
    ##example: [char[]](77,105,99,114,111,115,111,102,116,92,87,105,110,100,111,119,115,92,84,101,109,112,108,97,116,101,115,92,108,111,103,46,116,120,116) -join '')")){

    m = re.search('\[char\[\]\]\(((\d+)+|,)+\)',sz0, re.IGNORECASE)
    if m is not None:
        sz = m.group(0)
        if fVerbose:
            print("GROUP: " + sz)
        b64buf = ''
        for c in re.split('[(,)]', sz):
            if c.isdigit():
                b64buf += chr(int(c))
        ##now get the largest string in the decoded buf
        out = sz0.replace(sz + " -join ''", b64buf )
        if fVerbose:
            print("OUT: " + out)
        return out

    #find strings like this and substitute the decoded content
    #[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQA6ADEAMQAxADEAMQAxADEAMQAxADEAOgAxADEAMQAxADEAMQAxADEAMQAxADoAMQAxADEAOgAxADEAMQA6AA=='
    m = re.search('\[Text\.Encoding\]::Unicode\.GetString\(\[Convert\]::FromBase64String\(\'[A-Za-z0-9=/]*\'\)',sz0, re.IGNORECASE)
    if m is not None:
        g = m.group()
        b64 = (g.split("'")[1].decode('base64'))
        b64 = "'" + re.sub(r'[^\x01-\x7f]',r'', b64) + "'"
        out = sz0[:m.start()] + b64 + sz0[m.end():]
        return out

    sz = sz1 = max(filter(None, re.split("[\\\\ '\";\)]", sz0)), key=len).strip()

    ## test to see if we have candidate Base64 text
    h = re.compile(r'[A-Za-z0-9+/=]{10,}$')
    m = h.match(sz)
    if m is not None: 
        out = sz = sz.decode('base64')
        fNotUnicode = False
        for i in range(0,10,2):
            if sz[i] in string.printable and ord(sz[i+1]) == 0x0:
                continue
            else:
                fNotUnicode = True
                break
        if fNotUnicode:
            if ord(sz[0]) == 0x1f and ord(sz[1]) == 0x8b:
                if fVerbose: print('Found GZip')
                sz2 = str(zlib.decompressobj(32 + zlib.MAX_WBITS).decompress(sz))
                p1 = sz0[0:sz0.find(sz1)]
                p1 = re.sub(r'[^\x01-\x7f]',r'', p1)
                p2 = sz2
                p3 = sz0[sz0.find(sz1) + len(sz1):]
                p3 = re.sub(r'[^\x01-\x7f]',r'', p3)
                out = p1 + p2 + p3
            elif re.search('deflate',sz0, re.IGNORECASE):
                if fVerbose: print('Found Deflate')
                sz2 = str(zlib.decompress( sz, -15))
                p1 = sz0[0:sz0.find(sz1)]
                p1 = re.sub(r'[^\x01-\x7f]',r'', p1)
                p2 = sz2
                p3 = sz0[sz0.find(sz1) + len(sz1):]
                p3 = re.sub(r'[^\x01-\x7f]',r'', p3)
                out = p1 + p2 + p3
            else:
                # Test to see if we can dissasemble at least a min amount of instructions
                # that suggest we have valid x86

                # if we find curly braces, that suggest the result is code not asm
                if sz.count('{') + sz.count('}') >= 1:
                    if len(sz) != len(sz0):
                        p1 = sz0[0:sz0.find(sz1)]
                        p2 = out
                        p3 = sz0[sz0.find(sz1) + len(sz1):]
                        out = p1 + p2 + p3
                else:
                    outputparamlst = process_instructions(sz)
                    if outputparamlst is not None and len(outputparamlst[0]) > 15:
                        if fVerbose: print('Found Possible Shellcode')
                        out = dumpShellcode(sz)

        else:
            try:
                sz2 = out = out.decode('utf16', 'ignore')
            except Exception as e1:
                print(e1)
            if len(sz1) != len(sz0):
                p1 = sz0[0:sz0.find(sz1)]
                p1 = re.sub(r'[^\x01-\x7f]',r'', p1)
                p2 = sz2
                p3 = sz0[sz0.find(sz1) + len(sz1):]
                p3 = re.sub(r'[^\x01-\x7f]',r'', p3)
                out = p1 + p2 + p3
    elif sz.find(',0x') > 0: 
        if fVerbose: print('Found Possible Shellcode')
        
        ## 0x6a,0x0,0x53,0xff,0xd5 --> 6f 6a 0 53 ff d5
        ## handle leading @( in Ps1 dropped by 06951164119c7b1704b3ab8d0474e609e852785e4e71fbf26061389f9ab12c6d. thx @r00tninja and @James_inthe_box 
        sz = sz.replace('@','').replace('(','')
        szbytes =  ''.join([chr(int(''.join(c), 16)) for c in sz.split(',')])

        out = dumpShellcode(szbytes)

    return out

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description= \
    """Attempt to decode PowerShell scripts by looking for some common encoded data. It defaults to reading from stdin.
    \n
    REQUIREMENTS: This script uses vivisect for PE parsing and dissasembly: https://github.com/vivisect/vivisect. Set the PYTHONPATH as appropriate.
    """
    )
    parser.add_argument('--recurse','-r', help='Recursively decode until done', action='store_true',default=False)
    parser.add_argument('--file','-f', help='Read input from a file', action='store', type=str, default=None)
    parser.add_argument('--verbose','-v', help='Enable verbose mode', action='store_true', default=False)
    parser.add_argument('--noshellcode','-nx', help='Don\'t attempt to decode encoded shellcode', action='store_false', default=True)
    parser.add_argument('--dumpapis','-api', help='Dump APIs and hashes', action='store_true', default=False)
    parser.add_argument('--apidb','-db', help='Load APIs and hashes from a DB', action='store', type=str,default=None)
    args = parser.parse_args()

    psz = sz = None
    fVerbose = args.verbose
    fDecodeShellcode = args.noshellcode
    szDbPath = args.apidb

    if args.dumpapis:
        fVerbose = True
        prepareAPIs()
        sys.exit(0)

    if args.file is not None:
        file = open(args.file, 'r')
        sz = ' '.join(file.readlines())
    else:
        sz = ' '.join(sys.stdin.readlines())
        
    if args.recurse:
        try:
            fRecurse = True
            while fRecurse:
                psz = str(sz)
                sz2 = xray(sz)
                if len(sz2) == 0:
                    fRecurse = False
                    print(psz)
                sz = sz2
        except:
            print(psz)
            pass
    else:
        psz = xray(sz)
        psz = re.sub(r'[^\x01-\x7f]',r'', psz)
        print(psz)
