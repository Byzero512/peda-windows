import gdb
import os
import sys

# python_site_packages_path='F:\\Python27\\Lib\\site-packages'
cwd=os.path.dirname(__file__)
sys.path.append(cwd)
# sys.path.append(python_site_packages_path)


from wibe import screen,regCom
def stop_handler(event):
    screen.con()
gdb.events.stop.connect(stop_handler)

class wibeCom(gdb.Command):

    def __init__(self,cmd,cmd_exec):
        super(wibeCom, self).__init__(cmd, gdb.COMMAND_USER)
        self.cmd=cmd
        self.cmd_exec=cmd_exec
    def invoke(self, arg, from_tty):
        args=gdb.string_to_argv(arg)
        (self.cmd_exec)(args)

cmd_str,cmd_exec=regCom()
for i in range(len(cmd_str)):
    wibeCom(cmd_str[i],cmd_exec[i])

"""
init.py
|
|
wibe.py
    class screen
    class cmd
    class warp
|
|
lib.py
    class proc
    class info
    class exec_cmd
    class parse
|
|
var.py
"""