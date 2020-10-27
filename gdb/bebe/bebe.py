import gdb
from lib import proc,info,parse,exec_cmd

# one command one function

class brk():
    @classmethod
    def nb(clx,args):
        proc_base=0
        if proc.is_pie():
            proc_base=proc.proc_base()
        for line in args:
            try:
                bp=info.calc(line)+proc_base
                brk_cmd = 'b *{}'.format(hex(bp))
                gdb.execute(brk_cmd)
            except:
                print('error when exec nb')
                pass
    @classmethod
    def bb(clx,args):
        cls.nb(args)
    @classmethod
    def lb(clx, args):
        libc_base = proc.libc_base()
        for line in args:
            try:
                brk_cmd = 'b *{}'.format(hex(libc_base+info.calc(line)))
                gdb.execute(brk_cmd)
            except:
                print('error when exec '+brk_cmd, 'offset is: '+line)
                pass

class wch():
    @classmethod
    def poff(clx,args):
        proc_base=proc.proc_base()
        if len(args)==1:
            addr=int(args[0],16)
            if(addr>=proc_base):
                    print(hex(addr-proc_base))
            else:
                print(hex(addr+proc_base))
        else:
            print('need one argument')        
    @classmethod
    def loff(clx,args):
        libc_base=proc.libc_base()
        if len(args)==1:
            addr = int(args[0], 16)
            if(addr >= libc_base):
                    print(hex(addr-libc_base))
            else:
                print(hex(addr+libc_base))
        else:
            print('need one argument')

    @classmethod
    def nx(clx,args):
        proc_base = 0
        if proc.is_pie():
            proc_base = proc.proc_base()
        nfu=None
        addr=None
        bit_cmd='wx'
        if proc.is_64():
            bit_cmd='gx'
        if len(args)>=2:
            if '/' not in args[0]:
                # nx offset length
                nfu = '/'+length+bit_cmd
                offset = info.calc(args[0])

            else:
                # nx/nfu offset
                nfu = args[0]
                offset = info.calc(args[1])

        else:
            # nx offset 20
            nfu = '/20'+bit_cmd
            offset = info.calc(args[0])

        addr = hex(proc_base+offset)
        exec_cmd.execute_exam(nfu,addr)
    @classmethod
    def xx(clx,args):
        clx.nx(args)

    @classmethod
    def nxc(clx,args):
        """
            nxc offset len, len default is 16
        """
        
        proc_base = 0
        if proc.is_pie():
            proc_base = proc.proc_base()
        nfu=None
        
        if len(args)>=2:
            nfu = "/"+args[1]+'c'
        else:
            nfu='/16c'

        offset = info.calc(args[0])
        proc_base = proc.proc_base()
        addr = hex(proc_base+offset)
        exec_cmd.execute_exam(nfu,addr)

    @classmethod
    def nxs(clx,args):
        """
            nxs offset len, len default is 4
        """

        proc_base = 0
        if proc.is_pie():
            proc_base = proc.proc_base()
        nfu=None
        if len(args)>=2:
            nfu='/'+args[1]+'s'
        else:
            nfu='/4s'
        offset = info.calc(args[0])
        addr = hex(proc_base+offset)
        exec_cmd.execute_exam(nfu,addr)

    @classmethod
    def bp(clx,args):
        nfu=None
        bit_cmd='wx'
        bp=info.reg('ebp')
        if proc.is_64():
            bit_cmd='gx'
            bp=info.reg('rbp')
        if len(args)>=2:
            if '/' not in args[0]:                   # bp offset len
                nfu = '/'+args[1]+bit_cmd
                offset=info.calc(args[0])

            else:                                   # bp/nfu offset
                nfu = args[0]
                offset=info.calc(args[1])
        else:
            nfu='/20'+bit_cmd
            offset=info.calc(args[0])

        addr = hex(bp-offset)
        exec_cmd.execute_exam(nfu,addr)

    @classmethod
    def bpc(clx,args):
        """
            bpc offset len
        """
        nfu = None
        bit_cmd = 'wx'
        bp = info.reg('ebp')
        if proc.is_64():
            bit_cmd = 'gx'
            bp = info.reg('rbp')

        if len(args) >= 2:                                 # bpc offset len
            nfu = '/'+args[1]+'c'
        else:
            nfu = '/16c'
        offset = info.calc(args[0])
        addr = bp-offset
        exec_cmd.execute_exam(nfu, addr)
    
    @classmethod
    def bps(clx,args):
        """
            bpc offset len
        """
        nfu = None
        bit_cmd = 'wx'
        bp = info.reg('ebp')
        if proc.is_64():
            bit_cmd = 'gx'
            bp = info.reg('rbp')

        if len(args)>=2:                                 # bpc offset len
            nfu='/'+args[1]+'s'
        else:
            nfu='/4s'
        offset = info.calc(args[0])
        addr = bp-offset
        exec_cmd.execute_exam(nfu,addr)

    @classmethod
    def sp(clx,args):
        nfu = None
        bit_cmd = 'wx'
        sp = info.reg('esp')
        if proc.is_64():
            bit_cmd = 'gx'
            sp = info.reg('rsp')
        if len(args) >= 2:
            if '/' not in args[0]:                   # bp offset len
                nfu = '/'+args[1]+bit_cmd
                offset = info.calc(args[0])

            else:                                   # bp/nfu offset
                nfu = args[0]
                offset = info.calc(args[1])
        else:
            nfu = '/20'+bit_cmd
            offset = info.calc(args[0])

        addr = hex(sp+offset)
        exec_cmd.execute_exam(nfu, addr)
    @classmethod
    def spc(clx,args):
        nfu = None
        bit_cmd = 'wx'
        sp = info.reg('esp')
        if proc.is_64():
            bit_cmd = 'gx'
            sp = info.reg('rsp')

        if len(args) >= 2:                                 # bpc offset len
            nfu = '/'+args[1]+'c'
        else:
            nfu = '/16c'
        offset = info.calc(args[0])
        addr = sp-offset
        exec_cmd.execute_exam(nfu, addr)
    @classmethod
    def sps(clx,args):
        nfu = None
        bit_cmd = 'wx'
        sp = info.reg('esp')
        if proc.is_64():
            bit_cmd = 'gx'
            sp = info.reg('rsp')

        if len(args) >= 2:                                 # bpc offset len
            nfu = '/'+args[1]+'s'
        else:
            nfu = '/4s'
        offset = info.calc(args[0])
        addr = sp-offset
        exec_cmd.execute_exam(nfu, addr)

    @classmethod
    def np(clx,args,nps_sub=None):
        addr = int(args[0], 16)
        # proc.parse_vmmap()
        row_num=proc.parse_vmmap(addr)          # not only get row_num, but also parse_vmmap
        np_show1=''
        np_show2=''
        if info.range(addr)=='proc':
            np_show1=parse.color(hex(addr).rjust(18, ' '),'green')
            np_show2= parse.color("[proc]", "green")

        elif info.range(addr) == 'libc':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'purple')
            np_show2 = parse.color("[libc]", "purple")
        elif info.range(addr) == 'ld':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'purple')
            np_show2 = parse.color("[ld]", "purple")
        
        elif info.range(addr) == 'heap':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'blue')
            np_show2 = parse.color("[heap]", "blue")
        elif info.range(addr) == 'stack':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'yellow')
            np_show2 = parse.color("[stack]", "yellow")
        
        elif info.range(addr) == 'mapped':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'white')
            np_show2 = parse.color("[mapped]", "white")
        elif info.range(addr) == 'other':
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'cyan')
            np_show2 = parse.color("other", "cyan")
        else:
            np_show1 = parse.color(hex(addr).rjust(18, ' '), 'red')
            np_show2 = parse.color("(nil)", "red")

        if nps_sub is None:
            print((np_show1+' --> '+np_show2+'  ').ljust(0x35, ' ')+str(row_num))
        else:
            return (np_show1+' --> '+np_show2).ljust(0x35, ' ')+'  '+str(row_num)

    @classmethod
    def nps(clx,args):
        if len(args)==0:
            if proc.is_64():
                addr=info.reg('rsp')
            else:
                addr=info.reg('esp')
        else:
            addr=int(args[0],16)
        num=0x20
        cap=4

        if len(args)>=2:
            num=info.calc(args[1])
        if proc.is_64():
            cap=8
        memory=info.read(addr,cap*num)
        for i in range(num):
            con=parse.u(memory[i*cap:(i+1)*cap],cap)
            show1 = parse.color(('[{}] '.format(hex(i))).rjust(12), 'yellow')
            show2 = '{}: '.format(hex(addr+cap*i))
            show3 = clx.np([hex(con)], 1)
            print(show1+show2+show3)
    @classmethod
    def z(clx,args):
        cap=4
        if proc.is_64():
            cap=8
        n=20
        addr=info.calc(args[0])
        if len(args)==2:
            n=info.calc(args[1])
        if n%2==1:
            n+=1
        mem=info.read(addr,n*cap)
        need_color_addr=[]
        color=[]
        all_con=[]
        x=0
        for i in range(int(len(mem)/(cap*2))):
            lddr=addr+i*cap*2
            lnum=parse.u(mem[i*cap*2:i*cap*2+cap],cap)
            rnum=parse.u(mem[i*cap*2+cap:i*cap*2+cap*2],cap)
            all_con+=[lddr,lnum,rnum]
            for a in [lnum,rnum]:
                if addr<=a<(addr+n*cap) and a not in color:
                    need_color_addr.append(a)
                    color.append(31+x%6)
                    x+=1
        payload=''
        for i in range(int(len(all_con)/3)):
            if all_con[3*i] in need_color_addr:
                payload+=parse.color(
                    hex(all_con[3*i]).strip('L'),
                    color[need_color_addr.index(all_con[3*i])]
                )+'\t'
            else:
                payload+=hex(all_con[3*i]).strip('L')+'\t'
            for j in all_con[3*i+1:3*i+3]:
                if j in need_color_addr:
                    payload+=parse.color(
                        '0x'+hex(j)[2:].rjust(cap*2,'0').strip('L'),
                        color[need_color_addr.index(j)]
                    )+'\t'
                elif j==0:
                    payload+='-'*(cap*2+2)+'\t'
                elif j==parse.u('\xff'*cap,cap):
                    payload+='*'*(cap*2+2)+'\t'
                else:
                    payload+='0x'+hex(j)[2:].strip('L').rjust(cap*2,'0')+'\t'
            payload+='\n'
        print(payload.strip('\n'))
    @classmethod
    def read(clx,args):
        addr=int(args[0],16)
        memory=info.read(addr&~(0xffff),0xffff)
        print(memory)
        if '\x0f\x05' in str(memory,"Latin1"):
            print("yes")
class iofile():
    iofile_flag = {
        # '_IO_MAGIC':0xFBAD0000,
        # '_OLD_STDIO_MAGIC':0xFABC0000,
        # '_IO_MAGIC_MASK':0xFFFF0000,
        '_IO_USER_BUF': 1,
        '_IO_UNBUFFERED': 2,
        '_IO_NO_READS': 4,
        '_IO_NO_WRITES': 8,
        '_IO_EOF_SEEN': 0x10,
        '_IO_ERR_SEEN': 0x20,
        '_IO_DELETE_DONT_CLOSE': 0x40,
        '_IO_LINKED': 0x80,
        '_IO_IN_BACKUP': 0x100,
        '_IO_LINE_BUF': 0x200,
        '_IO_TIED_PUT_GET': 0x400,
        '_IO_CURRENTLY_PUTTING': 0x800,
        '_IO_IS_APPENDING': 0x1000,
        '_IO_IS_FILEBUF': 0x2000,
        '_IO_BAD_SEEN': 0x4000,
        '_IO_USER_LOCK': 0x8000
    }
    _IO_FILE_PLUS={
        'i386':{
            '_flags':0x0,
            '_IO_read_ptr':0x8,
            '_IO_read_end':0x1c,
            '_IO_read_base': 0x20,
            '_IO_write_base': 0x24,
            '_IO_write_ptr': 0x28,
            '_IO_write_end': 0x3c,
            '_IO_buf_base': 0x40,
            '_IO_buf_end': 0x44,
            '_IO_save_base': 0x48,
            '_IO_backup_base': 0x4c,
            '_IO_save_end': 0x50,
            '_markers': 0x54,
            '_chain': 0x58,
            '_fileno': 0x5c,
            '_flags2':0x60 
        },
        'amd64':{
            '_flags': 0x0,
            '_IO_read_ptr': 0x8,
            '_IO_read_end': 0x10,
            '_IO_read_base': 0x18,

            '_IO_write_base': 0x20,
            '_IO_write_ptr': 0x28,
            '_IO_write_end': 0x30,

            '_IO_buf_base': 0x38,
            '_IO_buf_end': 0x40,

            '_IO_save_base': 0x48,
            '_IO_backup_base': 0x50,
            '_IO_save_end': 0x58,

            '_markers': 0x60,
            '_chain': 0x68,
            '_fileno': 0x70,
            '_flags2': 0x74,
        }
    }
    @classmethod
    def nflag(clx,args):
        addr = info.calc(args[0])
        flag = info.value(addr)
        key = list(clx.iofile_flag.keys())
        value = list(clx.iofile_flag.values())
        flag_bits = ""
        for i in range(len(value)):
            if flag & value[i]:
                flag_bits += ('{}\n'.format(key[i])).rjust(25, ' ')
        payload = parse.color("[_IO_FILE->flag]:", 'green')+'\n'
        payload += parse.color(flag_bits, 'red').strip('\n')
        payload += parse.color("=========================", 'cyan')
        print(payload)

    @classmethod
    def nfile(clx,args):
        cap=8
        length=0x40
        arch='amd64'
        if proc.is_32():
            cap=4
            length=0x28
            arch='i386'
        clx.nflag(args)
        addr=int(args[0],16)
        def getvalue(key, arch=arch,addr=addr):
            return info.value(addr+clx._IO_FILE_PLUS[arch].get(key))
        def buf():
            print(parse.color("[_IO_FILE->Buffer]:", 'green'))
            buf_base=getvalue('_IO_buf_base')
            buf_end=getvalue('_IO_buf_end')
            print(parse.color('[6]'+'_IO_buf_base'.rjust(20,' ')+
                ' --> '+hex(buf_base), 'yellow'))
            print(parse.color('[7]'+'_IO_buf_end'.rjust(20, ' ') +
                ' --> '+hex(buf_end), 'yellow'))
            if buf_base == buf_end:
                print(parse.color('\tBase == End: Buffer not malloced', 'white'))
            print(parse.color("=========================", 'cyan'))
        def read_buf():
            print(parse.color("[_IO_FILE->Read]:", 'green'))
            read_base=getvalue('_IO_read_base')
            read_end=getvalue('_IO_read_end')
            read_ptr=getvalue('_IO_read_ptr')
            print(parse.color('[2]'+'_IO_read_base'.rjust(20,' ')
                +' --> '+hex(read_base), 'blue'))
            print(parse.color(
                '[1]'+'_IO_read_end'.rjust(20, ' ')+' --> '+hex(read_end), 'blue'))
            print(parse.color(
                '[0]'+'_IO_read_ptr'.rjust(20, ' ')+' --> '+hex(read_ptr), 'blue'))
            if read_base == read_end:
                print(parse.color('\tBase == End: Read Buffer not used','white'))
            else:
                if read_ptr<read_end:
                    print(parse.color('\tPtr < End: Read Buffer have space left', 'white'))
                elif read_ptr==read_end:
                    print(parse.color('\tPtr == End: Read Buffer empty or full', 'white'))
            print(parse.color("=========================", 'cyan'))
        def write_buf():
            print(parse.color("[_IO_FILE->Write]:", 'green'))
            write_base=getvalue('_IO_write_base')
            write_end=getvalue('_IO_write_end')
            write_ptr=getvalue('_IO_write_ptr')

            print(parse.color(
                '[3]'+'_IO_write_base'.rjust(20, ' ')+' --> '+hex(write_base), 'blue'))
            print(parse.color(
                '[5]'+"_IO_write_end".rjust(20, ' ')+' --> '+hex(write_end), 'blue'))
            print(parse.color('[4]'+'_IO_write_ptr'.rjust(20, ' ') +
                ' --> '+hex(write_ptr), 'blue'))
            if write_base == write_end:
                print(parse.color('\tBase == End: Write Buffer not used', 'white'))
            else:
                if write_ptr<write_end:
                    print(parse.color('\tPtr < End: Write Buffer have space left', 'white'))
                elif write_ptr == write_end:
                    print(parse.color('\tPtr == End: Write Buffer empty or full', 'white'))
            print(parse.color("=========================", 'cyan'))
        buf()
        read_buf()
        write_buf()

class pc():
    @classmethod
    def rejmp(clx,args):
        ip=0
        if proc.is_64():
            ip=info.reg('rip')
        elif proc.is_32():
            ip=info.reg('eip')
        opcode=info.opcode(ip)
        def is_jump():
            jump_opcode = ['jmp', 'je', 'jne'
                           'jg', 'jge', 'ja', 'jae', 'jl', 'jle',
                           'jb', 'jbe', 'jo', 'jno', 'jz', 'jnz'
                           ]
            if opcode in jump_opcode:
                return True
            return False

        if is_jump():
            EFLAGS_CF = 1 << 0
            EFLAGS_PF = 1 << 2
            EFLAGS_AF = 1 << 4
            EFLAGS_ZF = 1 << 6
            EFLAGS_SF = 1 << 7
            EFLAGS_TF = 1 << 8
            EFLAGS_IF = 1 << 9
            EFLAGS_DF = 1 << 10
            EFLAGS_OF = 1 << 11
            def parse_eflags():
                eflags = {"CF": 0, "PF": 0, "AF": 0, "ZF": 0,
                        "SF": 0, "TF": 0, "IF": 0, "DF": 0, "OF": 0}
                eflags_value = info.reg('eflags')
                eflags["CF"] = bool(eflags_value & EFLAGS_CF)
                eflags["PF"] = bool(eflags_value & EFLAGS_PF)
                eflags["AF"] = bool(eflags_value & EFLAGS_AF)
                eflags["ZF"] = bool(eflags_value & EFLAGS_ZF)
                eflags["SF"] = bool(eflags_value & EFLAGS_SF)
                eflags["TF"] = bool(eflags_value & EFLAGS_TF)
                eflags["IF"] = bool(eflags_value & EFLAGS_IF)
                eflags["DF"] = bool(eflags_value & EFLAGS_DF)
                eflags["OF"] = bool(eflags_value & EFLAGS_OF)
                return (eflags,eflags_value)
            (eflags,eflags_value)=parse_eflags()
            def jump_taken():
                if opcode == "jmp":
                    return True
                if opcode == "je" and eflags["ZF"]:
                    return True
                if opcode == "jne" and not eflags["ZF"]:
                    return True
                if opcode == "jg" and not eflags["ZF"] and (eflags["SF"] == eflags["OF"]):
                    return True
                if opcode == "jge" and (eflags["SF"] == eflags["OF"]):
                    return True
                if opcode == "ja" and not eflags["CF"] and not eflags["ZF"]:
                    return True
                if opcode == "jae" and not eflags["CF"]:
                    return True
                if opcode == "jl" and (eflags["SF"] != eflags["OF"]):
                    return True
                if opcode == "jle" and (eflags["ZF"] or (eflags["SF"] != eflags["OF"])):
                    return True
                if opcode == "jb" and eflags["CF"]:
                    return True
                if opcode == "jbe" and (eflags["CF"] or eflags["ZF"]):
                    return True
                if opcode == "jo" and eflags["OF"]:
                    return True
                if opcode == "jno" and not eflags["OF"]:
                    return True
                if opcode == "jz" and eflags["ZF"]:
                    return True
                if opcode == "jnz" and eflags["OF"]:
                    return True
                return False
            if jump_taken():
                def reverse_taken():
                    """
                        change jump to not jump
                    """
                    if opcode=='je':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jne':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jg':
                        new_eflags_value=((eflags_value|EFLAGS_ZF)|EFLAGS_SF)&(~EFLAGS_OF)
                    elif opcode=='jge':
                        new_eflags_value=eflags_value|EFLAGS_SF&(~EFLAGS_OF)
                    elif opcode=='ja':
                        new_eflags_value=eflags_value|EFLAGS_CF|EFLAGS_ZF
                    elif opcode=='jae':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jl':
                        new_eflags_value=eflags_value|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jle':
                        new_eflags_value=(eflags_value&~EFLAGS_ZF)|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jb':
                        new_eflags_value=eflags_value&(~EFLAGS_CF)
                    elif opcode=='jbe':
                        new_eflags_value=(eflags_value&(~EFLAGS_CF))&(~EFLAGS_ZF)
                    elif opcode=='jo':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    elif opcode=='jno':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    elif opcode=='jz':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jnz':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    else:
                        print("error: no matach condition jump ins")
                        return
                    gdb.execute('set $eflags={}'.format(hex(new_eflags_value)))
                reverse_taken()
            else:
                def reverse_not_taken():
                    """
                        change not jump to jump
                    """
                    if opcode == 'je':
                        new_eflags_value = eflags_value | EFLAGS_ZF
                    elif opcode == 'jne':
                        new_eflags_value = eflags_value & (~EFLAGS_ZF)
                    elif opcode == 'jg':
                        new_eflags_value = (eflags_value & (
                            ~EFLAGS_ZF)) | EFLAGS_SF | EFLAGS_OF
                    elif opcode == 'jge':
                        new_eflags_value = eflags_value | EFLAGS_SF | EFLAGS_OF
                    elif opcode == 'ja':
                        new_eflags_value = (eflags_value & (
                            ~EFLAGS_CF)) & (~EFLAGS_ZF)
                    elif opcode == 'jae':
                        new_eflags_value = eflags_value & (~EFLAGS_CF)
                    elif opcode == 'jl':
                        new_eflags_value = (
                            eflags_value | EFLAGS_SF) & (~EFLAGS_OF)
                    elif opcode == 'jle':
                        new_eflags_value = eflags_value | EFLAGS_ZF
                    elif opcode == 'jb':
                        new_eflags_value = eflags_value | EFLAGS_CF
                    elif opcode == 'jbe':
                        new_eflags_value = eflags_value | EFLAGS_CF
                    elif opcode == 'jo':
                        new_eflags_value = eflags_value | EFLAGS_OF
                    elif opcode == 'jno':
                        new_eflags_value = eflags_value & (~EFLAGS_OF)
                    elif opcode == 'jz':
                        new_eflags_value = eflags_value | EFLAGS_ZF
                    elif opcode == 'jnz':
                        new_eflags_value = eflags_value | EFLAGS_OF
                    else:
                        print("error: no matach condition jump ins")
                        return
                    gdb.execute('set $eflags={}'.format(hex(new_eflags_value)))
                reverse_not_taken()
    @classmethod
    def rep(clx,args):
        cmd_str=args[0]
        n=info.calc(args[1])
        for i in range(n):
            exec_cmd.execute(cmd_str)
    
    @classmethod # not test on thread
    def nt(clx,args):
        top=args[0]
        ip='rip'
        if proc.is_32():
            ip='eip'
        while(1):
            exec_cmd.execute('ni')
            addr=info.reg(ip)
            cop=info.opcode(addr)
            if top==cop:
                break
        return gdb.execute('context')
                
    @classmethod # not test on thread
    def st(clx,args):
        top=args[0]
        ip='rip'
        if proc.is_32():
            ip='eip'
        while(1):
            exec_cmd.execute('si')
            addr=info.reg(ip)
            cop=info.opcode(addr)
            if top==cop:
                break
        return gdb.execute('context')
    @classmethod
    def fix(clx,args):
        address=int(args[0],16)
        print("set (char *){}=0x41".format(hex(address)))
        print("set $rip={}".format(hex(address)))
        gdb.execute("set *(char *){}=0x41".format(hex(address)))
        gdb.execute("set $rip={}".format(hex(address)))


class heap():
    @classmethod
    def nf(clx,args):
        """
            based on pwngdb
        """
        cap = 4
        if proc.is_64():
            cap = 8
        addr = info.calc(args[0])
        gdb.execute('free '+hex(addr+cap*2))

class fmt():
    @classmethod
    def fmtoff(clx,args):
        fmtstr_addr = int(args[0], 16)
        if proc.is_64():
            sp = info.reg('rsp')
            offset = hex((int)((fmtstr_addr-sp)/8)+6)
            print("<amd64> fmtstr offset --> "+offset)
        elif proc.is_32():
            sp = info.reg('esp')
            offset = hex((int)((fmtstr_addr-sp)/4))
            print("<i386>  fmtstr offset --> "+offset)

class misc():
    @classmethod  # connect to remote debbugger
    def con(clx,args):
        ip='localhost'
        port='1234'
        if len(args)==1:
            idx=args[0].find(':')
            if idx!=-1:
                ip=(args[0])[0:idx+1]
                port=(args[0])[idx+1:]
            else:
                port=args[0]
        elif len(args)==2:
            ip=args[0]
            port=args[1]
        exec_cmd.execute('target remote {}:{}'.format(ip,port))

    @classmethod  #  generate structure
    def gstru(clx,args):
        symbol='_IO_wide_data'
        # cm='print &((struct {}*)0)->'.format(symbol)
        # keys=gdb.lookup_type(symbol).keys()
        # print(keys)
        # rs='{\n'
        # for i in keys:
        #     l=exec_cmd.execute(cm+i).strip('\n')
        #     lidx=l.find('0x')
        #     ridx=l.find(' ',lidx)
        #     if ridx!=-1:
        #         l=l[lidx:ridx+1]
        #     else:
        #         l=l[lidx:]
        #     off=int(l,16)
        #     rs+='\t"{}": {},\n'.format(i,hex(off))
        # rs+='}'
        # print(rs)

        main_arena = gdb.lookup_symbol(symbol)[0]
        print(main_arena)
        main_arena=main_arena.type
        print(main_arena.keys())


# register command
clas=[brk,wch,iofile,pc,heap,fmt,misc]
def regCom():
    cmd_str=[]
    cmd_exec=[]
    for c in clas:
        for f in dir(c):
            if not f.startswith('__'):
                cmd_str.append(f)
                cmd_exec.append(getattr(c,f))
    return (cmd_str,cmd_exec)