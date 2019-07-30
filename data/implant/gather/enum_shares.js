try
{
    var WshNetwork = WScript.CreateObject("WScript.Network");
    var oDrives = WshNetwork.EnumNetworkDrives();

    var ret = "";
    for (i = 0; i < oDrives.length; i += 2)
    {
        ret += oDrives.Item(i) + " = " + oDrives.Item(i + 1) + "\n";
    }

    entypreter.work.report(ret);
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
