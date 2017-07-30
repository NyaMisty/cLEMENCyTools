#!/usr/bin/env python3
import argparse, multiprocessing, os, re, select, socket, subprocess, sys, traceback

ptrace_flag = os.path.join(os.path.dirname(__file__), 'ptrace-flag')

def do_task(filename):
    pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    with open(filename) as f, \
         subprocess.Popen([ptrace_flag, '0x409f98', opt_emu,
                           opt_binary],
                          pass_fds=[pair[1].fileno()],
                          stdin=pair[1],
                          stdout=pair[1]) as p:
    #with open(filename) as f, \
    #     subprocess.Popen(['/tmp/a.py'],
    #                      pass_fds=[pair[1].fileno()],
    #                      stdin=pair[1],
    #                      stdout=pair[1]) as p:
        pair[1].close()
        try:
            for line in f.readlines():
                input()
                if line.startswith('C '):
                    buf = bytearray()
                    i = 0
                    while i < len(line):
                        if line[i] == '\\':
                            buf.append(int(line[i+2:i+4], 16))
                            i += 4
                        else:
                            buf.append(ord(line[i]))
                            i += 1
                    buf = bytes(buf)
                    if opt_verbose:
                        print('C', buf)
                    pair[0].send(buf)
                elif line.startswith('S '):
                    if opt_verbose:
                        print('S')
                    rl, _, _ = select.select([], [], [], opt_timeout)
                    if rl:
                        pair[0].recv(1024*1024)
                elif line.startswith('delay '):
                    timeout = min(float(line[6:]), opt_timeout)
                    if opt_verbose:
                        print('delay')
                    rl, _, _ = select.select([], [], [], timeout)
                    if rl:
                        pair[0].recv(1024*1024)
            pair[0].shutdown(socket.SHUT_RD)
            if p.wait(opt_timeout) == 99:
                print('Suspect: {}'.format(filename))
        except:
            traceback.print_exc()
            try:
                p.kill()
            except:
                pass

def main():
    global opt_binary, opt_emu, opt_timeout, opt_verbose
    ap = argparse.ArgumentParser(description='convert between 9-bit cLEMENCy and 16-bit binary', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
    ''')
    ap.add_argument('-b', '--binary', help='cLEMENCy binary')
    ap.add_argument('-e', '--emu', default='./clemency_emu', help='path to clemency_emu')
    ap.add_argument('-j', '--jobs', type=int, default=0, help='number of parallel workers (default: 0, the number of cores)')
    ap.add_argument('-i', '--ignore', nargs='*', default=[], help='list of patterns to ignore')
    ap.add_argument('-t', '--timeout', type=float, default=0.5, help='list of patterns to ignore')
    ap.add_argument('-v', '--verbose', action='store_true', help='list of patterns to ignore')
    ap.add_argument('input', nargs='*', help='')
    args = ap.parse_args()
    opt_binary = args.binary
    opt_emu = args.emu
    opt_timeout = args.timeout
    opt_verbose = args.verbose
    if not opt_binary or not os.path.isfile(opt_binary):
        print('Please specify -b/--binary hello.bin', file=sys.stderr)
        return 1
    if not os.path.isfile(opt_emu):
        print('Please specify -e/--emu clemency_emu', file=sys.stderr)
        return 1

    if not os.path.isfile(ptrace_flag):
        print('Please run make -C tool ptrace_flag', file=sys.stderr)
        return 1

    tasks = []

    def walk(path):
        for i in args.ignore:
            if re.search(i, path):
                return
        if os.path.isdir(path):
            for i in os.listdir(path):
                walk(os.path.join(path, i))
        elif re.search(r'\.txt$', path):
            tasks.append(path)

    for i in args.input:
        walk(i)

    if len(tasks):
        jobs = args.jobs or multiprocessing.cpu_count()
        if jobs == 1:
            for task in tasks:
                do_task(task)
        else:
            pool = multiprocessing.Pool(jobs)
            for _ in pool.imap_unordered(do_task, tasks, 1):
                pass
            pool.close()

if __name__ == '__main__':
    sys.exit(main())
