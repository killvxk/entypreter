try
{
    var path = "System\\CurrentControlSet\\Control\\Terminal Server";
    var key = "fDenyTsConnections";

    entypreter.registry.write(entypreter.registry.HKLM, path, key, ~MODE~, entypreter.registry.DWORD);
    var out = entypreter.registry.read(entypreter.registry.HKLM, path, key, entypreter.registry.DWORD);

    if (out.uValue != ~MODE~)
        throw new Error("Unable to write to registry key.");

    entypreter.work.report("");
}
catch(e)
{
    entypreter.work.error(e);
}

entypreter.exit()
