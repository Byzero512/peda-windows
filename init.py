import gdb
import os
import sys

python_site_packages_path='F:\\Python27\\Lib\\site-packages'
cwd=os.path.dirname(__file__)
sys.path.append(cwd)
sys.path.append(python_site_packages_path)


from wibe import *
def stop_handler(event):
    screen.con()
gdb.events.stop.connect(stop_handler)

class wibe(gdb.Command):

    def __init__(self,cmd,cmd_exec):
        super(wibe, self).__init__(cmd, gdb.COMMAND_USER)
        self.cmd=cmd
        self.cmd_exec=cmd_exec
    def invoke(self, arg, from_tty):
        args=gdb.string_to_argv(arg)
        (self.cmd_exec)(args)

for i in range(len(wibe_cmd)):
    wibe(wibe_cmd[i],wibe_exec[i])