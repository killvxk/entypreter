try
{
    var voiceObj = new ActiveXObject("sapi.spvoice");

    for (var i = 0; i < 50; ++i)
    {
        entypreter.WS.SendKeys(String.fromCharCode(0xAF));
    }
    voiceObj.Speak("~MESSAGE~");
    entypreter.work.report("");
}
catch (e)
{
    entypreter.work.error(e);
}
entypreter.exit();
