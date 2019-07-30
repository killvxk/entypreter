try
{
    var html = new ActiveXObject("htmlfile");
    var text = html.parentWindow.clipboardData.getData("text");
    entypreter.work.report(text);
}
catch (e)
{
    entypreter.work.error(e)
}

entypreter.exit();
