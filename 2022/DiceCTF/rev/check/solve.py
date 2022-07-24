import gdb

gdb.execute("b *strcmp")
gdb.execute("run")
for i in range(40):
    gdb.execute("n")