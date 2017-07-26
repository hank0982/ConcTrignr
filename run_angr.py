import angr
import claripy

sym_argv = claripy.BVS('sym_argv', 16)

p = angr.Project('programs/c.out')
state = p.factory.entry_state(args=[p.filename, sym_argv])
pg = p.factory.path_group(state)

while len(pg.active) > 0:
    pg.step()

for dd in pg.deadended:
    res = dd.state.se.any_str(sym_argv)
    print "[+] New Input:", res
