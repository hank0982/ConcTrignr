import angr
import claripy
import sys
import time
import argparse

from termcolor import colored


def run_symexe(path, argv_size=2, show_bytes=True, show_model=False):
    sym_argv = claripy.BVS('sym_argv', argv_size * 8)

    try:
        p = angr.Project(path)
    except:
        print colored('Invalid path: \"' + path + '\"', 'red')
        return None

    state = p.factory.entry_state(args=[p.filename, sym_argv])
    pg = p.factory.path_group(state)
    
    while len(pg.active) > 0:
        pg.step()

    print colored('[*] Paths found: ' + str(len(pg.deadended)), 'white')

    for dd in pg.deadended:
        res = dd.state.se.any_str(sym_argv)
        if show_bytes:
            print colored('[+] New Input: ' + res + ' |', 'green'),
            print colored('ASCII:', 'cyan'),
            for char in res:
                print colored(ord(char), 'cyan'),
            print ''
            if show_model:
                print colored(str(dd.state.se.constraints), 'yellow')
        else:
            print colored('[+] New Input: ' + res, 'green')


if __name__ == '__main__':
    print '\n\n'
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--constraints", help="Print generated model",action="store_true")
    parser.add_argument("binary_path", type=str, help="Binary path")
    args = parser.parse_args()

    run_symexe(args.binary_path, 12, show_model=args.constraints)
