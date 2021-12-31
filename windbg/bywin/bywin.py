import pykd
import struct
import sys
import os

class cmd():
    @classmethod
    def exec_cmd(clx,cmd):
        return pykd.dbgCommand(cmd)
    @classmethod
    def exec_print(clx,cmd):
        print(pykd.dbgCommand(cmd).strip("\n"))
    @classmethod
    def alias(clx,cmd,func):
        print("as {} !py -g {} {}".format(cmd, os.path.dirname(sys.argv[0])+"\\bywin.py",func))
        pykd.dbgCommand("as {} !py -g {} {}".format(cmd, os.path.dirname(sys.argv[0])+"\\bywin.py",func))
class info():
    @classmethod
    def reg(clx,name):
        return pykd.reg(name)
    @classmethod
    def read(clx,addr,n):
        try:
            rsl=pykd.loadBytes(addr,n)
            rs=''
            for r in rsl:
                rs+=chr(r)
            return rs
        except:
            raise(Exception)
        # return ''.join(pykd.loadBytes(addr,n))
    @classmethod
    def getsize_t(clx,addr):
        size_t=clx.read(addr,process.size_t)
        if process.is_32():
            return struct.unpack("<I",parse.toByte(size_t))[0]
        elif process.is_64():
            return struct.unpack("<Q",parse.toByte(size_t))[0]
        else:
            raise(Exception)
    @classmethod
    def symbol(clx,addr):
        # sym=pykd.findSymbol(addr)
        # try:
        #     if int(sym,16)==addr:
        #         return ''
        #     return sym
        # except:
        #     return ''
        return ''
    @classmethod
    def write(clx,addr,con):
        listBytes=[]
        for r in con:
            listBytes.append(ord(r))
        pykd.writeBytes(addr,listBytes)
    @classmethod
    def ins_addr(clx,offset):
        addr=pykd.disasm().findOffset(offset)
        asm_str=pykd.disasm(addr).opmnemo()
        return (addr,asm_str)
    @classmethod
    def is_cstr(clx,addr):
        try:
            pykd.loadCStr(addr)
        except:
            return False
        return True
    @classmethod
    def is_ustr(clx,addr):
        try:
            pykd.loadWStr(addr)
        except:
            return False
        return True        
    @classmethod
    def xinfo(clx,addr,n=4,is_regs=False):
        value=None
        _addr=0
        rstr=''
        rstr+='0x{{:0{}x}}'.format(process.size_t*2).format(addr)#hex(addr)
        sym=info.symbol(addr)
        if sym:
            rstr+='({})'.format(sym)
        if is_regs is False:
            rstr+=': '
        _rstr=rstr
        try:
            for i in range(n):
                value=info.getsize_t(addr)
                if i !=0 or is_regs:
                    rstr+=" -> "
                _rstr=rstr
                _addr=addr
                addr=value                
                if is_regs:
                    info.getsize_t(value)
                rstr+='0x{{:0{}x}}'.format(process.size_t*2).format(value)
                if is_regs is False:
                    _rstr=rstr
                sym=info.symbol(value)
                if sym:
                    rstr+='({})'.format(sym)
                # _addr=addr
                # addr=value
        except:
            if is_regs is False:
                fmt='("{}")'
            else:
                fmt='"{}"'
            try:
                cstr=pykd.loadCStr(_addr)

                if (cstr and value>0x1f and
                        (
                            (ord(cstr[0])<0x7f) and
                            (cstr[:1:]=='' or ord(cstr[:1:])<0x7f) and
                            (cstr[1:2:]=='' or ord(cstr[1:2:])<0x7f)
                        )
                    ):
                        rstr=_rstr+fmt.format(cstr.replace("\n","\\n")[:process.size_t*2-2:])
                elif is_regs:
                    rstr=_rstr+'0x{{:0{}x}}'.format(process.size_t*2).format(value)
            except:
                # try:
                #     wstr=pykd.loadUnicodeString(_addr)
                #     if wstr:
                #         rstr=_rstr+fmt.format(wstr[:process.size_t*2-2:])
                #     elif is_regs:
                #         rstr=_rstr+'0x{{:0{}x}}'.format(process.size_t*2).format(value)
                # except:
                if value is not None and is_regs:
                    rstr+='0x{{:0{}x}}'.format(process.size_t*2).format(value)
                    # pass
        return rstr

class process():
    _regs=[]
    _sp=''
    _pc=''
    size_t=4
    @classmethod 
    def init(clx):
        if process.is_32():
            process._regs = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp', 'eip',"efl"]
            process._sp = 'esp'
            process._pc = 'eip'
            process.size_t=4
        elif process.is_64():
            process._regs = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp', 'rsp', 'rip',"efl"]
            process._sp = 'rsp'
            process._pc = 'rip'
            process.size_t=8
    @classmethod
    def arch(clx):
        cpu_mode = pykd.getCPUMode()
        if cpu_mode == pykd.CPUType.I386:
            return 32
        elif cpu_mode == pykd.CPUType.AMD64:
            return 64
        else:
            return 0
    @classmethod
    def is_64(clx):
        return clx.arch()==64
    @classmethod
    def is_32(clx):
        return clx.arch()==32

class parse():
    @classmethod
    def color(clx):
        pass
    @classmethod
    def toStr(clx,Byte):
        if sys.version_info[0]==3:
            return str(Byte,'Latin1')
        return Byte #.decode('Latin1')
    @classmethod
    def toByte(clx,Str):
        if sys.version_info[0]==3:
            # print(sys.getdefaultencoding())
            return bytes(Str,"Latin1")
        return bytes(Str)

class context():
    @classmethod
    def regs(clx):
        for i in range(0,len(process._regs),2):
            rstr="{:3s}: ".format(process._regs[i])
            rstr+=info.xinfo(info.reg(process._regs[i]),n=1,is_regs=True)
            rstr=rstr.ljust(45,' ')
            rstr+="   "
            rstr+="{:3s}: ".format(process._regs[i+1])
            rstr+=info.xinfo(info.reg(process._regs[i+1]),n=1,is_regs=True)
            print(rstr)
    @classmethod
    def asm(clx):
        # addr1=info.ins_addr(-5)
        # addr2=info.ins_addr(5)
        # cmd.exec_print("uu {} {}".format(hex(addr1),hex(addr2)))
        t="   "
        for i in range(-5,6):
            addr,asm_str=info.ins_addr(i)
            if i==0:
                t="==>"
            print("{} {}:    {}".format(t,hex(addr).strip("L"),asm_str))
            t="   "

    @classmethod
    def stack(clx):
        sp=info.reg(process._sp)
        for i in range(10):
            print('[{:02x}] '.format(i*process.size_t)+info.xinfo(sp+i*process.size_t))
    @classmethod
    def show(clx):
        print('--------------------------------------------------------------------')
        try:
            context.asm()
        except:
            pass
        print('--------------------------------------------------------------------')
        try:
            context.regs()
        except:
            pass
        print('--------------------------------------------------------------------')
        try:
            context.stack()
        except:
            pass

# .load E:\ShareDir\building\bywin\pykd_ext_2.0.0.24\x64\pykd.dll
# !py -g E:\ShareDir\building\bywin\bywin.py

# def test():
#     cmd.exec_print("lm")
    # print(info.read(0xfffff8066ae00000,4))
    # print(info.symbol(0xfffff8066b2486f0))
    # info.write(0xfffff8066ae00000,'\xff\xff\xff\xff\xff\xff\xff\xff')
    # print(hex(info.ins_addr(-1)))
    # print(process.arch())
    # print(process.is_64())
    # print(process.is_32())
    # context.asm()
    # context.regs()
    # context.stack()
    # context.show()
    # print(dir(pykd.disasm(0xfffff8047fb67ed9)))
    # asm_str=pykd.disasm(0xfffff8047fb67ed9).opmnemo()
    # print(asm_str)
    # print(pykd.disasm(0xfffff8047fb67ed9).jumprel())
    # print(op_str,asm_str)
# test()
def lstr(addr):
    # print(pykd.loadCStr(addr))
    print(pykd.loadWStr(addr))
    # print(pykd.loadUnicodeString(addr))
class break_event(pykd.eventHandler):
    def __init__(self):
        pykd.eventHandler.__init__(self)
    def onExecutionStatusChange(self, status):
        if status == pykd.executionStatus.Break:
            context.show()

process.init()
if __name__ == "__main__":
    if len(sys.argv)>1:
        command=sys.argv[1]
        if command=='xinfo':
            print(info.xinfo(int(sys.argv[2],16)))
        elif command=='pcon':
            context.show()
        elif command=='lstr':
            lstr(int(sys.argv[2],16))
    # cmd.alias("xinfo",'test')
    # a=break_event()
    # context.show()