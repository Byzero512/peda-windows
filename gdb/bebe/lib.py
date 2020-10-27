import gdb
import var
import struct
import re
import subprocess
import hashlib

class info():
    @classmethod
    def reg(clx,reg_name):
        """
            return register value such as:
                reg("rip")
        """
        reg_value = gdb.selected_frame().read_register(reg_name)
        return int(reg_value)
            
    @classmethod
    def read(clx,addr, length):
        """
            return content of memory
        """
        gdb_inferior = gdb.selected_inferior()
        memory = gdb_inferior.read_memory(addr, length)
        return memory.tobytes()
    
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
    def range(clx,addr):
        """
            judge where the addr belong to
        """
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
        if is_belong(proc.libc_beg, proc.libc_end):
            return 'libc'
        if is_belong(proc.ld_beg, proc.ld_end):
            return 'ld'
        if is_belong(proc.stack_beg, proc.stack_end):
            return 'stack'
        if is_belong(proc.heap_beg, proc.heap_end):
            return 'heap'
        if is_belong(proc.mapped_beg, proc.mapped_end):
            return 'mapped'
        if is_belong(proc.other_beg, proc.other_end):
            return 'other'
        return 'nil'

    @classmethod
    def ins(clx,addr):
        line=exec_cmd.execute('x/i {}'.format(hex(addr))).strip('\n')
        return line[line.find('\t')+1:]
    
    @classmethod
    def opcode(clx,addr):
        ins=clx.ins(addr)
        return ins[0:ins.find(' ')]

class proc():
    proc_beg=[]
    proc_end=[]
    libc_beg=[]
    libc_end=[]
    ld_beg=[]
    ld_end=[]
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
    def is_alive(clx):
        try:
            return gdb.selected_inferior().pid > 0
        except Exception:
            return False
        return False

    @classmethod
    def pid(clx):
	    return gdb.selected_inferior().pid

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
    def proc_path(clx):
        inf_id = gdb.selected_inferior().num
        if inf_id in var.proc_path:
            return (var.proc_path)[inf_id]
        else:
            all_inferiors = gdb.execute(
                'info inferiors', to_string=True).strip('\n')
            cur_inferior = (all_inferiors.split('\n'))[inf_id]
            fpath = cur_inferior.replace('*', '')
            fpath = (fpath.replace(str(inf_id), '', 1)).lstrip(' ').strip(' ')
            fpath = fpath[8:]
            fpath = fpath[fpath.find(' '):].lstrip(' ')
            var.proc_path.update({inf_id: fpath})
            return fpath

    @classmethod
    def libc_path(clx):
        return
    @classmethod
    def proc_base(clx):
        vmmap=clx.vmmap()
        def ret_proc_base(vmmap):
            if vmmap:
                proc_path = clx.proc_path()
                maps = vmmap.split('\n')
                
                for line in maps:
                    if proc_path in line:
                        index = line.find('-')
                        proc_base = int(line[0:index],16)
                        return proc_base
            else:
                if clx.is_64():
                    if clx.is_pie():
                        return 0x555555554000
                    else:
                        return 0x400000
                else:
                    if clx.is_pie():
                        return 0x56555000
                    else:
                        return 0x08048000
        return ret_proc_base(vmmap)

    @classmethod
    def libc_base(clx):
        vmmap=clx.vmmap()
        def ret_libc_base(vmmap):
            maps=vmmap.split('\n')
            for line in maps:
                if "libc" in line:
                    index=line.find('-')
                    libc_base=int(line[0:index],16)
                    return libc_base
        return ret_libc_base(vmmap)

    @classmethod
    def vmmap(clx):
        pid = clx.pid()
        if pid != 0:
            vmmap_path = '/proc/'+str(pid)+'/maps'
            vmmap_content = open(vmmap_path).read()
            return vmmap_content.strip('\n')
        else:
            return None

    @classmethod
    def parse_vmmap(clx,addr=0):

        maps=clx.vmmap()#.split('\n')
        maps_hash=hashlib.md5(maps.encode("utf-8"))
        maps=maps.split('\n')
        if maps_hash == clx.maps_hash and addr == 0:
            return
        if maps_hash != clx.maps_hash:
            clx.proc_beg = []
            clx.proc_end = []
            clx.libc_beg = []
            clx.libc_end = []
            clx.ld_beg = []
            clx.ld_end = []
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
                if clx.maps_hash == maps_hash:
                    break
            i += 1
            if maps_hash != clx.maps_hash:
                if clx.proc_path() in line:
                    clx.proc_beg.append(beg)
                    clx.proc_end.append(end)
                elif 'libc' in line:
                    clx.libc_beg.append(beg)
                    clx.libc_end.append(end)
                elif '[heap]' in line:
                    clx.heap_beg.append(beg)
                    clx.heap_end.append(end)
                elif '[stack]' in line:
                    clx.stack_beg.append(beg)
                    clx.stack_end.append(end)
                elif 'ld' in line:
                    clx.ld_beg.append(beg)
                    clx.ld_end.append(end)
                elif 'mapped' in line or '[' not in line:
                    clx.mapped_beg.append(beg)
                    clx.mapped_end.append(end)
                else:
                    clx.other_beg.append(beg)
                    clx.other_end.append(end)
        clx.maps_hash == maps_hash
        return res

    @classmethod
    def is_64(clx):
        return clx.arch() == "i386:x86-64"

    @classmethod
    def is_32(clx):
        return clx.arch() == "i386"

    @classmethod
    def is_pie(clx):
        procname = clx.proc_path()
        result = subprocess.check_output("readelf -h " + "\"" + procname + "\"", shell=True).decode('utf8')
        if re.search("DYN", result):
            return True
        else:
            return False

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
        if type(color)==str:
            return "\033[0;{}m{}\033[0m".format(c.get(color), content)
        else:
            return "\033[0;{}m{}\033[0m".format(color, content)
    @classmethod
    def u(clx,content,length=None):
        # print(type(content))
        if isinstance(content,str):
            content=bytes(content,"Latin1")
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
    
    @classmethod
    def p(clx,content,length):
        if length==8:
            return struct.pack('<Q',content)
        return struct.pack('<I',content)

class exec_cmd():
    @classmethod
    def execute(clx,cmd):
        return gdb.execute(cmd,to_string=True)
    @classmethod
    def execute_exam(clx,nfu,addr):
        nfu_cmd='x{} {}'.format(nfu,addr)
        gdb.execute(nfu_cmd)
