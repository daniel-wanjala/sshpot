import json
import time
import os
import datetime
import twisted.python.logfile

class JsonLog(object):
    def __init__(self):
        dire = os.path.dirname('./log/')
        self.outfile = twisted.python.logfile.DailyLogFile("ssh.log", dire, defaultMode=0o664)
    def get_log(self, user, password, rhost):

        data = {}
         # safeconfigparser used to read conf-file
        data['timestamp'] = datetime.datetime.fromtimestamp(time.time()).isoformat()
        data['dst_ip'] = "127.0.0.1"
        data['dst_port'] = 2222
        data['src_ip'] = rhost
        # data['src_port'] = rport
        data['user:passwd'] = user.decode("utf-8")+":"+password.decode("utf-8")
        line = json.dumps(data)
        self.outfile.write(line + "\n")
        self.outfile.flush()
