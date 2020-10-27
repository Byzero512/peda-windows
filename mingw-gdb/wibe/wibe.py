from lib import *
import gdb

REGISTERS = {
    'i386': ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip","eflags"],
    'i386:x86-64': [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8",
        "r9", "r10", "r11", "r12", "r13", "r14", "r15",'eflags'
    ]
}
EFLAGS_CF = 1 << 0
EFLAGS_PF = 1 << 2
EFLAGS_AF = 1 << 4
EFLAGS_ZF = 1 << 6
EFLAGS_SF = 1 << 7
EFLAGS_TF = 1 << 8
EFLAGS_IF = 1 << 9
EFLAGS_DF = 1 << 10
EFLAGS_OF = 1 << 11

class screen():
    @classmethod
    def con(clx):
        def reg():
            print('------------------------------register----------------------------') 
            l=warp.reg()
            for i in l:
                print(i)
        def code():
            print('------------------------------code----------------------------')
            l=warp.code()
            for i in l:
                print(i)
        def stack():
            print('------------------------------stack----------------------------')
            l=warp.stack()
            for i in l:
                print(i)
        
        proc.parse_vmmap()
        reg()
        code()
        stack()

class cmd():
    # context
    @classmethod
    def vmmap(clx,args=[]):
        n=0
        if args:
            if args[0]=='most':
                n=1
            elif args[0]=='all':
                n=2
        print(proc.vmmap(n))
    @classmethod
    def pcon(clx,args=[]):
        clx.preg()
        clx.pcode()
        clx.pstack()
    @classmethod
    def pstack(clx,args=[]):
        print('------------------------------stack----------------------------')
        n=16
        if len(args)==1:
            n=int(int(args[0],16))
        l=warp.stack(n)
        for i in l:
            print(i)
    @classmethod
    def pcode(clx,args=[]):
        print('------------------------------code----------------------------')
        n=5
        if len(args)==1:
            n=int(int(args[0],10)/2)
        l=warp.code(prev_count=n,next_count=n)
        for i in l:
            print(i)
    @classmethod
    def preg(clx,args=[]):
        print('------------------------------register----------------------------') 
        l=warp.reg()
        for i in l:
            print(i)
    @classmethod
    def maps(clx,args=[]):

        ll=['image']
        ll+=args
        show_all=0
        if "all" in ll:
            show_all=1

        for l in proc.simplify_vmmap:
            if not show_all and l[2] not in ll:
                continue
            addr="{} - {}".format(hex(l[0])[2:].rjust(16,'0'),hex(l[1])[2:].rjust(16,'0'))
            typestr=('\t{}\t\t'.format(l[2])).ljust(9,' ')
            detilas=l[3]
            print(addr+typestr+detilas)
        # print(payload)
    @classmethod
    def xinfo(clx,args):
        addr=int(args[0],16)
        for l in proc.maps:
            if l[0]<=addr<l[1]:
                beg=hex(l[0])
                end=hex(l[1])
                print(parse.color("xinfo:",'cyan'))
                print('\t'+warp.xinfo_color(addr))
                print(parse.color("details:",'cyan'))
                print('\t{} - {}  {}  {}  {}'.format(beg,end,l[2],l[3],l[4]))
                break

    # pc
    @classmethod
    def rejmp(clx,args=None):
        warp.code(rejmp=1)

    # brk
    @classmethod
    def nb(clx,args):
        proc_base=proc.proc_base()
        for line in args:
            try:
                brk_cmd = 'b *{}'.format(hex(proc_base+info.calc(line)))
                gdb.execute(brk_cmd)
            except:
                print('error when exec '+brk_cmd,'offset is: '+line)
                pass

    # wch
    @classmethod
    def nx(clx,args):
        proc_base = proc.proc_base()
        # if not proc.is_pie():
            # proc_base = 0
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
    def nxc(clx,args):
        """
            nxc offset len, len default is 16
        """
        
        if not proc.is_pie():
            proc_base=0
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

        proc_base=proc.proc_base()
        if not proc.is_pie():
            proc_base=0
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
            lnum=parse.u(mem[i*cap*2:i*cap*2+cap])
            rnum=parse.u(mem[i*cap*2+cap:i*cap*2+cap*2])
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
                elif j==parse.u('\xff'*cap):
                    payload+='*'*(cap*2+2)+'\t'
                else:
                    payload+='0x'+hex(j)[2:].strip('L').rjust(cap*2,'0')+'\t'
            payload+='\n'
        print(payload.strip('\n'))
    @classmethod 
    def parse(clx,args):
        heapbase=info.calc(args[0])
        print("CompatibilityFlags: 0x{:X}".format(parse.u(info.read(heapbase+0x78,4),4)))
        FrontEndHeap=parse.u(info.read(heapbase+0x198,8),8)
        print('FrontEndHeap: 0x{:X}'.format(FrontEndHeap))
        print('SegmentInfoArrays addr: 0x{:X}'.format(FrontEndHeap+0x4a8))

class warp():
    @classmethod
    def xinfo_color(clx,addr):
        def color(con,con_type):
            c='white'
            if con_type=='proc':
                c='green'
            elif con_type=='dll':
                c='red'
            elif con_type=='stack':
                c='yellow'
            elif con_type=='heap':
                c='cyan'
            return parse.color(con,c)

        (cur_xinfo,just_num)=info.xinfo(addr)

        color_xinfo=''
        if just_num:
            for i in range(len(cur_xinfo)):
                color_xinfo += color(cur_xinfo[i], info.range(int(cur_xinfo[i], 16)))

                if i != len(cur_xinfo) - 1:
                    color_xinfo += '  -->  '
        else:
            for i in range(len(cur_xinfo)):
                if i != len(cur_xinfo) - 2:
                    color_xinfo += color(cur_xinfo[i], info.range(int(cur_xinfo[i], 16))) + '  -->  '
                else:
                    color_xinfo += color(cur_xinfo[i],info.range(int(cur_xinfo[i],16))) + ' {}'.format(
                        cur_xinfo[i + 1])
                    break
        return color_xinfo        
        
    @classmethod
    def reg(clx):
        res=[]
        for reg in REGISTERS[proc.arch()]:
            show_payload=parse.color(reg.rjust(6,' '),'cyan')+': '
            show_payload+=clx.xinfo_color(info.reg(reg))
            res.append(show_payload)
        return res

    @classmethod
    def code(clx,addr=None,prev_count=5,next_count=5,rejmp=False):
        
        if addr is None:
            ip='eip'
            if proc.is_64():
                ip='rip'
            addr=info.reg(ip)            
            
        def is_jump(addr=addr):
            opcode=info.opcode(addr)
            jump_opcode=['jmp','je','jne',
            'jg','jge','ja','jae','jl','jle',
            'jb','jbe','jo','jno','jz','jnz',
            ]
            if opcode in jump_opcode:
                return True
            return False  
        
        def parse_eflags():

            flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
            eflags = info.reg('eflags')
            if not eflags:
                return None
            flags["CF"] = bool(eflags & EFLAGS_CF)
            flags["PF"] = bool(eflags & EFLAGS_PF)
            flags["AF"] = bool(eflags & EFLAGS_AF)
            flags["ZF"] = bool(eflags & EFLAGS_ZF)
            flags["SF"] = bool(eflags & EFLAGS_SF)
            flags["TF"] = bool(eflags & EFLAGS_TF)
            flags["IF"] = bool(eflags & EFLAGS_IF)
            flags["DF"] = bool(eflags & EFLAGS_DF)
            flags["OF"] = bool(eflags & EFLAGS_OF)

            return flags  

        def is_jump_taken(addr=addr):              

            opcode=info.opcode(addr)
            eflags=parse_eflags()
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

        if rejmp:
            if is_jump(addr=addr):
                opcode=info.opcode(addr)
                eflags_value=info.reg('eflags')
                if is_jump_taken():
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
                else:
                    if opcode=='je':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jne':
                        new_eflags_value=eflags_value&(~EFLAGS_ZF)
                    elif opcode=='jg':
                        new_eflags_value=(eflags_value&(~EFLAGS_ZF))|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='jge':
                        new_eflags_value=eflags_value|EFLAGS_SF|EFLAGS_OF
                    elif opcode=='ja':
                        new_eflags_value=(eflags_value&(~EFLAGS_CF))&(~EFLAGS_ZF)
                    elif opcode=='jae':
                        new_eflags_value=eflags_value&(~EFLAGS_CF)
                    elif opcode=='jl':
                        new_eflags_value=(eflags_value|EFLAGS_SF)&(~EFLAGS_OF)
                    elif opcode=='jle':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jb':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jbe':
                        new_eflags_value=eflags_value|EFLAGS_CF
                    elif opcode=='jo':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    elif opcode=='jno':
                        new_eflags_value=eflags_value&(~EFLAGS_OF)
                    elif opcode=='jz':
                        new_eflags_value=eflags_value|EFLAGS_ZF
                    elif opcode=='jnz':
                        new_eflags_value=eflags_value|EFLAGS_OF
                    else:
                        print("error: no matach condition jump ins")
                        return
                    gdb.execute('set $eflags={}'.format(hex(new_eflags_value)))                    
            return

        def prev_ins(addr=addr,count=prev_count):
            if count>0:
                res = []
                backward = 64 + 16 * count
                for i in range(backward):
                    try:
                        exec_payload = 'x/x {}'.format(hex(addr - backward + i))
                        exec_cmd.execute(exec_payload)
                    except:
                        continue
                    code = exec_cmd.execute("disassemble {}, {}".format(
                        hex(addr - backward + i), hex(addr + 1)))
                    if code and ("%x" % addr) in code:
                        lines = code.strip().splitlines()[1:-1]
                        if len(lines) > count and "(bad)" not in " ".join(lines):
                            for line in lines[-count - 1:-1]:
                                res.append(line)
                            return res
            return []         
        def next_ins(addr=addr,count=next_count):
            if count>0:
                res = []
                code = exec_cmd.execute("x/{}i {}".format(count + 1, addr))
                if not code:
                    return []
                lines = code.strip().splitlines()
                for i in range(1, count + 1):
                    res.append(lines[i])
                return res
            return []
        def cur_ins(addr=addr):
            return [parse.color(exec_cmd.execute('x/i {}'.format(addr)).strip(),'cyan')]

        def args(addr=addr):
            
            if info.opcode(addr)=='call':
                res=[]
                try:
                    if proc.is_32():
                        sp=info.reg('esp')
                        r=[info.value(sp),info.value(sp+4),info.value(sp+0x8)]
                        # for i in range(3):
                            # addr=info.value(sp+4*i)
                            # res.append('[arg{}]: '.format(i)+clx.xinfo_color(addr))
                    else:
                        r=[info.reg('rcx'),info.reg('rdx'),info.reg('r8')]
                    for i in range(3):
                        res.append('[arg{}]: '.format(i)+clx.xinfo_color(r[i]))
                    return res
                except:
                    return []
            return []

        all_ins=prev_ins()
        all_ins+=[parse.color('------------------------------','cyan')]
        all_ins+=cur_ins()+next_ins()
        taken_str=' '*32
        if is_jump():
            if is_jump_taken():
                taken_str+='jump taken'
            else:
                taken_str+='jump not taken'
            all_ins.append(parse.color(taken_str,'red'))
        all_ins+=args()

        return all_ins
    
    @classmethod
    def stack(clx,count=16):
        # proc.parse_vmmap()
        cap=4
        sp='esp'
        if proc.is_64():
            cap=8
            sp='rsp'
        sp=info.reg(sp)
        res=[]
        try:
            for i in range(count):
                res.append(clx.xinfo_color(sp+i*cap))
            return res
        except:
            return res

exec_cmd.execute('set prompt {}'.format(parse.color('wibe$ ','yellow')))

# wibe_cmd=[
#     'vmmap','pcon','pstack','pcode','preg','rejmp','disable_pie','enable_pie'
# ]
# wibe_exec=[
#     cmd.vmmap,cmd.pcon,cmd.pstack,cmd.pcode,cmd.preg,cmd.rejmp,proc.disable_pie,proc.enable_pie
# ]

clas=[cmd]
def regCom():
    cmd_str=[]
    cmd_exec=[]
    for c in clas:
        for f in dir(c):
            if not f.startswith('__'):
                cmd_str.append(f)
                cmd_exec.append(getattr(c,f))
    # cmd_str+=['disable_pie','enable_pie']
    # cmd_exec+=[proc.disable_pie,proc.enable_pie]
    return (cmd_str,cmd_exec)