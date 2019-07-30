# Entynet Remete Administration Tool (entypreter)

    INFO: The Entynet Remote Administration Tool (entypreter) 
    is a Windows post-exploitation rootkit similar to other penetration 
    testing tools such as Meterpreter and Powershell Invader Framework. 
    The major difference is that entypreter does most of its operations 
    using Windows Script Host (a.k.a. JScript/VBScript), with compatibility 
    in the core to support a default installation of Windows 2000 with no service 
    packs (and potentially even versions of NT4) all the way through Windows 10.
   
***

# Stagers and Implants

    INFO: Stagers hook target session and 
    allow you to use implants. Implants 
    starts jobs on remote session.
    
## Stagers

    INFO: Stagers hook target session 
    and allow you to use implants.

Module | Description
--------|------------
stager/js/mshta | serves payloads using MSHTA.exe HTML Applications.
stager/js/regsvr | serves payloads using regsvr32.exe COM+ scriptlets.
stager/js/wmic | serves payloads using WMIC XSL.
stager/js/rundll32_js | serves payloads using rundll32.exe.
stager/js/disk | serves payloads using files on disk.

## Implants

    INFO: Implants starts 
    jobs on remote session.

Module | Description
--------|------------
implant/elevate/bypassuac_eventvwr | Uses enigma0x3's eventvwr.exe exploit to bypass UAC on Windows 7, 8, and 10.
implant/elevate/bypassuac_sdclt | Uses enigma0x3's sdclt.exe exploit to bypass UAC on Windows 10.
implant/fun/session | Maxes volume and opens The Cranberries YouTube in a hidden window.
implant/fun/voice | Plays a message over text-to-speech.
implant/gather/clipboard | Retrieves the current content of the user clipboard.
implant/gather/enum_domain_info | Retrieve information about the Windows domain.
implant/gather/enum_printers | Retrieve information about printer connections.
implant/gather/hashdump_sam | Retrieves hashed passwords from the SAM hive.
implant/gather/hashdump_dc | Domain controller hashes from the NTDS.dit file.
implant/gather/user_hunter | Locate users logged on to domain computers (using Dynamic Wrapper X).
implant/inject/mimikatz_dynwrapx | Injects a reflective-loaded DLL to run powerkatz.dll (using Dynamic Wrapper X).
implant/inject/mimikatz_dotnet2js | Injects a reflective-loaded DLL to run powerkatz.dll (@tirannido DotNetToJS).
implant/inject/shellcode_excel | Runs arbitrary shellcode payload (if Excel is installed).
implant/manage/enable_rdesktop | Enables remote desktop on the target.
implant/manage/exec_cmd | Run an arbitrary command on the target, and optionally receive the output.
implant/persist/add_user | Create a local/domain user.
implant/persist/registry | Add an entypreter payload to the registry.
implant/persist/schtasks | Add an entypreter payload as a Scheduled Task.
implant/persist/wmi | Add an entypreter payload as a WMI subscription.
implant/phishing/password_box | Prompt a user to enter their password.
implant/pivot/stage_wmi | Hook a session on another machine using WMI.
implant/pivot/exec_psexec | Run a command on another machine using psexec from sysinternals.
implant/scan/tcp | Uses HTTP to scan open TCP ports on the target session LAN.
implant/utils/download_file | Downloads a file from the target session.
implant/utils/multi_module | Run a number of implants in succession.
implant/utils/upload_file | Uploads a file from the listening server to the target sessions.

***

# TLS Communications

    INFO: To enable TLS communications, you will need 
    to host your entypreter stager on a valid domain 
    (i.e. malicious.com) with a known Root CA signed 
    certificate. Windows will check its certificate 
    store and will NOT allow a self-signed certificate.

> Free certificates are available at: https://letsencrypt.org/getting-started/

    (entypreter: sta/js/mshta)$ set CERTPATH /path/to/fullchain.pem
    (entypreter: sta/js/mshta)$ set KEYPATH  /path/to/privkey.pem
    
***
    
# Terms of use

    This tool is only for educational purposes only.
    Use this tool wisely and never without permission.
    I am not responsible for anything you do with this tool.
    
***

# Entypreter apache license

    Copyright (C) 2016 - 2018 Entynetproject, Inc.

    Licensed under the Apache License, Version 2.0 (the "License"); you may not
    use the software except in compliance with the License.

    You may obtain a copy of the License at:

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations under
    the License.

    Disclaimer:
    Usage of entypreter for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local, state,
    federal, and international laws. Developers assume no liability and are not
    responsible for any misuse or damage caused by this program.
    
***

# Thats all!
