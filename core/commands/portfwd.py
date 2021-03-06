DESCRIPTION = "Stub command for help text."
hidden_command = True

def autocomplete(shell, line, text, state):
    return None

def help(shell):
    msg = """
Unlike most connectback RATs, Entypreter does not rely on a single long-lived TCP connection. Windows Script Host isn't smart enough to do that. Instead, Entypreter uses repeated HTTP requests in separate connections. It is important that you not modify the URL of a listener between when Entypreter spits it out and when it is executed on the host because the very first thing Entypreter is going to try and do after the first connection is establish a second connection - and it's going to try and make the second connection using the URL Entypreter knows about, not the one you executed.

So! How do I use Entypreter through a port forward? Easy! Just make Entypreter generate the correct URL right out of the gate. Set SRVHOST and SRVPORT to whatever address the target box needs to initiate connections to. It doesn't matter if that's not a local address on the host where Entypreter is running. Entypreter will just bind 0.0.0.0 and accept connections from anywhere.
""".strip()
    try:
        import textwrap
        msg2 = ""
        for paragraph in msg.split("\n\n"):
            msg2 += "\n".join(textwrap.wrap(paragraph))
            msg2 += "\n\n"
        msg = msg2.strip()
    except:
        pass
    shell.print_plain(msg)

def execute(shell, cmd):
    shell.print_plain("Sorry! This is just a stub-command to explain how to stage Entypreter through a port forward. Windows Script Host is not smart enough for Entypreter to do its own port forwards. You probably just want to stage a native RAT.");
