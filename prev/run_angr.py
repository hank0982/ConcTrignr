import angr
import claripy


project_path = '/home/neil/ConcTriton/programs/c.out'


def main():
    def getFuncAddress(funcName, plt=None):
        found = [
            addr for addr, func in cfg.kb.functions.iteritems()
            if funcName == func.name and (plt is None or func.is_plt == plt)
        ]
        if len(found) > 0:
            print "Found " + funcName + "'s address at " + hex(found[0]) + "!"
            return found[0]
        else:
            raise Exception("No address found for function: " + funcName)

    proj = angr.Project(project_path, load_options={'auto_load_libs': False})

    argv = [proj.filename]
    sym_arg = claripy.BVS('sym_arg', 1 * 8)
    argv.append(sym_arg)

    cfg = proj.analyses.CFG(fail_fast=True)
    print cfg
    addrFoo = getFuncAddress("check", plt=False)
    # addrBar = getFuncAddress("Bar", plt=False)
    # addrBogus = getFuncAddress("Bogus", plt=False)
    state = proj.factory.entry_state(args=argv)
    path_group = proj.factory.path_group(state)

    def check(p):
        if (p.state.ip.args[0] == addrFoo):
            print "Foo triggered"
            return True
        else:
            return False

    path_group = path_group.explore(find=check)
    found = path_group.found
    if (len(found) > 0):
        print path_group
        print path_group.found
        print found[0].state.se.constraints
        found = path_group.found[0]
        result = found.state.se.any_str(argv[1])
        print("argv=", result)

if __name__ == "__main__":
    main()
    print 'End'
