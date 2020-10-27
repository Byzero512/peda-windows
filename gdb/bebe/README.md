# bebe
a gdb script for debug when pwn

# setup
> echo source init.py >> ~/.gdbinit 

## brk
1. nb: use offset to insert breakpoint
    + nb offset: same with "b \*(process_base+offset)"
2. lb: use offset to brk libc 
 
## wch
1. nx: use offset to examine program memory
    + nx/nfu offset: same with "x/nfu (process_base+offset)"
2. bp: examine stack using offset to $rbp
    + bp/nfu offset: same with "x/nfu ($rbp-num)"
3. sp
4. poff
5. loff
6. np: use to find an addr belong to which range(program or libc or heap or or stack or mmaped or other)
    + np addr
7. nps: use to find the value near addr(provided by argument) belong to which range
 
## iofile
1. nflag: parse _IO_FILE_flags
2. nfile: parse _IO_FILE buffer

 ## fmt
 1. fmtoff: use to find addr(or fmtstr addr in memory) offset to $sp  
    + fmtoff addr.

## pc
1. rejmp: then opcode is condition jmp, change eflags, then can reverse the jmp target

