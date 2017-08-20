#!/usr/bin/env python

import angr
import claripy
import os
import sys
import time
import argparse
import subprocess

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

    results = []
    for dd in pg.deadended:
        res = dd.state.se.any_str(sym_argv)
        results.append(res)
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

    return results


if __name__ == '__main__':
    print '\n\n'
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--constraints", help="Show generated model", action="store_true")
    parser.add_argument("-C", "--compile", type=int, help="Compile from source, if C > 0, -O option will be used")
    parser.add_argument("-l", "--length", type=int, help="Stdin size")
    parser.add_argument("-r", "--run_program", help="Run program after analysis", action="store_true")
    parser.add_argument("-s", "--summary", type=int, help="Display summary information")
    parser.add_argument("file_path", type=str, help="Binary path")
    args = parser.parse_args()

    if args.compile is not None:
        print colored('[*] Compiling...', 'cyan')
        bin_dir, filename = os.path.split(args.file_path)
        if args.compile != 0:
            cmd = ' '.join(['gcc -o', os.path.join(bin_dir, filename[0] + '.out'), 
                           '-O' + str(args.compile), args.file_path])
        else:
            cmd = ' '.join(['gcc -o', os.path.join(bin_dir, filename[0] + '.out'), args.file_path])
        print cmd
        os.system(cmd)
        print colored('[*] Compile completed\n', 'green')
        bin_path = os.path.join(bin_dir, filename[0] + '.out')
    else:
        bin_path = args.file_path

    print colored('[*] Analysing...', 'cyan')
    if args.length is None:
        results = run_symexe(bin_path, 10, show_model=args.constraints)
    else:
        results = run_symexe(bin_path, args.length, show_model=args.constraints)
    print colored('[*] Analysis completed\n', 'green')

    tests = []
    if results is not None and args.run_program:
        bin_dir, filename = os.path.split(args.file_path)
        for i, res in enumerate(results):
            print colored('[*] Result ' + str(i + 1) + ':', 'yellow')
            res = res.replace('\x00', '')
            print 'Calling: ' + ' '.join([os.path.join(bin_dir, filename[0] + '.out'), res])
            pipe = subprocess.Popen([os.path.join(bin_dir, filename[0] + '.out'), res])
            single_run = pipe.wait()
            output = 'return value:' + str(single_run) + '\n'
            tests.append(single_run)
            print colored(output, 'yellow')

        if args.summary is not None:
            cnt = 0
            for i in set(tests):
                if i in list(range(len(results))):
                    cnt += 1
            coverage = 100 * cnt / args.summary

            if coverage <= 100 and coverage > 95:
                color = 'green'
            elif coverage <= 95 and coverage > 85:
                color = 'cyan'
            elif coverage <= 85 and coverage > 60:
                color = 'yellow'
            else:
                color = 'red'
            print colored('Coverage: ' + '%.2f%%\n' % coverage, color)
