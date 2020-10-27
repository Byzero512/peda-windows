from bywin import cmd,break_event,context,process
if __name__ == "__main__":
    # process.init()
    cmd.alias("xinfo",'xinfo')
    cmd.alias("pcon",'pcon')
    cmd.alias("lstr",'lstr')
    a=break_event()
    context.show()