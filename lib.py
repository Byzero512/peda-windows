import gdb
import struct
import subprocess
import sys
import string
import hashlib

import var

class info():
    @classmethod
    def reg(clx,reg_name):
        reg_value = gdb.selected_frame().read_register(reg_name)
        return int(reg_value.cast(gdb.lookup_type('unsigned long')))
    @classmethod
    def read(clx,addr,length):
        gdb_inferior = gdb.selected_inferior()
        memory = gdb_inferior.read_memory(addr, length)
        return memory

    @classmethod
    def value(clx,addr):
        """
            return the value of the memory by the given addr
        """
        if proc.is_64():
            return parse.u(clx.read(addr,8),8)
        elif proc.is_32():
            return parse.u(clx.read(addr,4),4)

    @classmethod
    def calc(clx,expr):
        """
            calc an expr based on hex
        """
        if expr[0]=='+' or expr[0]=='-':
            expr='0'+expr
        result = 0
        symbol_type = [1]
        symbol_posi = [-1]

        for i in range(len(expr)):
            if expr[i] == '+':
                symbol_type.append(1)
                symbol_posi.append(i)

            if expr[i] == '-':
                symbol_type.append(0)
                symbol_posi.append(i)

        for i in range(len(symbol_type)):

            l_posi = symbol_posi[i]+1
            if i != len(symbol_type)-1:

                r_posi = symbol_posi[i+1]
            else:
                r_posi = len(expr)
            num = int(expr[l_posi:r_posi], 16)

            if symbol_type[i] == 1:
                result = result+num
            else:
                result = result-num
        return result

    @classmethod
    def ins(clx,addr):
        line=exec_cmd.execute('x/i {}'.format(hex(addr))).strip('\n')
        return line[line.find('\t')+1:].strip(' ')
    
    @classmethod
    def opcode(clx,addr):
        ins=clx.ins(addr)
        return ins[0:ins.find(' ')]

    @classmethod
    def range(clx,addr):
        """
            judge where the addr belong to
        """
        # proc.parse_vmmap()
        def is_belong(beg,end,addr=addr):
            length=len(beg)
            if length:
                if addr<beg[0] or addr>=end[-1]:
                    return False
                for i in range(length):
                    if beg[i]<=addr<end[i]:
                        return True
            return False
        
        if is_belong(proc.proc_beg,proc.proc_end):
            return 'proc'
        if is_belong(proc.dll_beg, proc.dll_end):
            return 'dll'
        if is_belong(proc.stack_beg,proc.stack_end):
            return 'stack'
        if is_belong(proc.heap_beg, proc.heap_end):
            return 'heap'
        if is_belong(proc.mapped_beg, proc.mapped_end):
            return 'mapped'
        if is_belong(proc.other_beg, proc.other_end):
            return 'other'
        return 'nil'

    @classmethod
    def xinfo_type(clx,addr):
        """
            return the data type in the addr
                type include:
                    anum 0
                    ins 1
                    str 2
        """

        if clx.value(addr)==0:
            return 0
        cap=4
        if proc.is_64():
           cap=8
        try:
            line = exec_cmd.execute('x/20i {}'.format(hex(addr)))
            if ('bad' not in line 
            and 'add    BYTE PTR [eax],al' not in line 
            and 'mov' in line):
                return 1  # an ins
            else:
                raise Exception
        except:
            line = clx.read(addr,cap)

            if(parse.is_str(line)):
                return 2
            return 0  # just a num

    @classmethod
    def xinfo(clx,addr,depth=5):
        """
            return a tuple: ([a1,a2,a3],type)
        """
        just_num = 1
        cxinfo = []
        last_addr = 0
        cxinfo.append(hex(addr))  # here no problem
        for i in range(depth):
            try:
                value = clx.value(addr)  # here may error
                cxinfo.append(hex(value))
                last_addr = addr
                addr = value
            except:
                if last_addr:
                    del (cxinfo[len(cxinfo) - 1])
                    value_type = clx.xinfo_type(last_addr)
                    
                    if value_type == 0:         # num
                        cxinfo.append(hex(addr))

                    elif value_type == 1:       # ins
                        just_num=0
                        ins='({})'.format(clx.ins(last_addr))
                        cxinfo.append(ins)

                    elif value_type == 2:       # str
                        just_num=0
                        astr = exec_cmd.execute('x/s {}'.format(hex(last_addr))).strip()
                        astr = '(' + astr[astr.find('\t') + 1:] + ')'
                        cxinfo.append(hex(clx.value(last_addr)))
                        cxinfo.append(astr)

                else:# error at the start
                    text=parse.p(addr)
                    if(parse.is_str(text)):
                       cxinfo.append('("{}")'.format(text))
                       just_num=0
                break

        for i in range(len(cxinfo)):
            cxinfo[i]=cxinfo[i].strip('L')
        return (cxinfo,just_num)

class proc():
    proc_beg=[]
    proc_end=[]
    dll_beg=[]
    dll_end=[]
    stack_beg=[]
    stack_end=[]
    heap_beg=[]
    heap_end=[]
    mapped_beg=[]
    mapped_end=[]
    other_beg=[]
    other_end=[]
    maps_hash=None
    @classmethod
    def is_alive(cls):
        """Check if GDB is running."""
        try:
            return gdb.selected_inferior().pid > 0
        except Exception:
            return False
        return False
    @classmethod
    def pid(clx):
        return gdb.selected_inferior().pid
    @classmethod
    def proc_path(clx):
        inf_id = gdb.selected_inferior().num
        if inf_id in var.proc_path:
            return (var.proc_path)[inf_id]
        else:
            all_inferiors=gdb.execute('info inferiors',to_string=True).strip('\n')
            cur_inferior = (all_inferiors.split('\n'))[inf_id]
            fpath = cur_inferior.replace('*', '')
            fpath = (fpath.replace(str(inf_id), '', 1)).lstrip(' ').strip(' ')
            fpath=fpath[8:]
            fpath=fpath[fpath.find(' '):].lstrip(' ')
            var.proc_path.update({inf_id:fpath})
            return fpath

    @classmethod
    def arch(clx):
        if clx.is_alive():
            arch = gdb.selected_frame().architecture()
            return arch.name()
        arch = gdb.execute("show architecture", to_string=True).strip()
        if "The target architecture is set automatically (currently " in arch:
            # architecture can be auto detected
            arch = arch.split("(currently ", 1)[1]
            arch = arch.split(")", 1)[0]
        elif "The target architecture is assumed to be " in arch:
            # architecture can be assumed
            arch = arch.replace("The target architecture is assumed to be ", "")
        else:
            # unknown, we throw an exception to be safe
            raise RuntimeError("Unknown architecture: {}".format(arch))
        return arch

    @classmethod
    def is_64(clx):
        return clx.arch() == "i386:x86-64"

    @classmethod
    def is_32(clx):
        return clx.arch() == "i386"
    
    @classmethod
    def vmmap(clx, show_level=0):
        vmmap_exec = 'vmmap.exe -pid {} '.format(clx.pid())
        if show_level == 2:
            vmmap_exec += '-all'
        elif show_level == 1:
            vmmap_exec += '-most'
        return subprocess.check_output(vmmap_exec, shell=True).strip('\n')

    @classmethod
    def parse_vmmap(clx,addr=0):

        maps=clx.vmmap(2)
        maps_hash=hashlib.md5(maps)
        maps=maps.split('\n')
        if maps_hash==clx.maps_hash and addr==0:
            return

        clx.proc_beg = []
        clx.proc_end = []
        clx.dll_beg = []
        clx.dll_end = []
        clx.stack_beg = []
        clx.stack_end = []
        clx.heap_beg = []
        clx.heap_end = []
        clx.mapped_beg = []
        clx.mapped_end = []
        clx.other_beg = []
        clx.other_end = []

        def parse_line(line):
            m=line.find('-')
            r=line.find(' ')
            return (int(line[0:m],16),int(line[m+1:r],16))
        i=0
        res=None
        for line in maps:
            (beg,end)=parse_line(line)

            if addr and (beg<=addr<end):
                res=i
                if clx.maps_hash==maps_hash:
                    break
            i+=1
            if maps_hash!=clx.maps_hash:
                if clx.proc_path() in line:
                    clx.proc_beg.append(beg)
                    clx.proc_end.append(end)
                elif 'dll' in line:
                    clx.dll_beg.append(beg)
                    clx.dll_end.append(end)
                elif 'Heap' in line:
                    clx.heap_beg.append(beg)
                    clx.heap_end.append(end)
                elif 'Stack' in line:
                    clx.stack_beg.append(beg)
                    clx.stack_end.append(end)
                # elif '[mapped]' in line or '[' not in line:
                    # clx.mapped_beg.append(beg)
                    # clx.mapped_end.append(end)
                else:
                    clx.other_beg.append(beg)
                    clx.other_end.append(end)
        # def show():
        #     # print(proc.proc_path())
        #     # print(clx.proc_beg)
        #     # print(clx.proc_end)
        #     # print(clx.dll_beg)
        #     # print(clx.dll_end)
        #     print(clx.stack_beg)
        #     print(clx.stack_end)
        #     # print(clx.heap_beg)
        #     # print(clx.heap_end)
        #     # print(clx.mapped_beg)
        #     # print(clx.mapped_end)
        #     # print(clx.other_beg)
        #     # print(clx.other_end)
        # show()
        clx.maps_hash==maps_hash
        return res


class exec_cmd():
    @classmethod
    def execute(clx,cmd):
        return gdb.execute(cmd,to_string=True)
    @classmethod
    def execute_exam(clx,nfu,addr):
        nfu_cmd='x{} {}'.format(nfu,addr)
        gdb.execute(nfu_cmd)

class parse():
    @classmethod
    def color(clx,content,color):
        c = {
            "black": 30,
            "red": 31,
            "green": 32,
            "yellow": 33,
            "blue": 34,
            "purple": 35,
            "cyan": 36,
            "white": 37,
        }
        return "\033[0;{}m{}\033[0m".format(c.get(color), content)
    
    @classmethod
    def u(clx,content,length=None):
        if length:
            if length==8:
                return struct.unpack('<Q',content)[0]
            elif length==4:
                return struct.unpack('<I',content)[0]
        else:
            if proc.is_64():
                return struct.unpack('<Q',content)[0]
            elif proc.is_32():
                return struct.unpack('<I',content)[0]
        return None
    @classmethod
    def p(clx,content,length=None):
        if length:
            if length==8:
                return struct.pack('<Q',content)
            elif length==4:
                return struct.pack('<I',content)
        else:
            if proc.is_64():
                return struct.pack('<Q',content)
            elif proc.is_32():
                return struct.pack('<I',content)

    @classmethod
    def is_str(clx,text,printables=""):
        python_version=sys.version_info[0]
        def b(s):
            if sys.version_info[0]==2:
                return s
            elif sys.version_info[0]==3:
                return s.encode("latin-1")
            return ""
        if python_version==3 and isinstance(text,str):
            text=b(text)
        return set(text)-set(b(string.printable)+b(printables))==set()
