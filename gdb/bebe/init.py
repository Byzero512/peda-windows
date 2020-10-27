import gdb
import os
import sys
cwd = os.path.dirname(__file__)
sys.path.append(cwd)

from bebe import regCom
class bebeCom(gdb.Command):
    def __init__(self, cmd,cmd_exec):
        self.cmd = cmd
        self.cmd_exec=cmd_exec
        super(bebeCom, self).__init__(cmd, gdb.COMMAND_SUPPORT, gdb.COMPLETE_NONE, True)
    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        (self.cmd_exec)(args)

cmd_str,cmd_exec=regCom()
for i in range(len(cmd_str)):
    bebeCom(cmd_str[i],cmd_exec[i])