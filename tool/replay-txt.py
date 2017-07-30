#!/usr/bin/env python3
import argparse, functools, multiprocessing, os, re, select, signal, socket, subprocess, sys, traceback

READ_FLAG_ADDR = 0x409f98
ptrace_flag = os.path.join(os.path.dirname(__file__), 'ptrace-flag')

def timeout(f):
    def handler(_signum, _frame):
        raise TimeoutError()

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        old = signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, opt_total_timeout, 0)
        try:
            ret = f(*args, **kwargs)
        finally:
            signal.signal(signal.SIGALRM, old)
            signal.setitimer(signal.ITIMER_REAL, 0, 0)
        return ret

    return wrapper

@timeout
def do_task1(filename):
    pair = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM, 0)
    pair[0].settimeout(opt_timeout)
    with open(filename) as f, \
         subprocess.Popen([ptrace_flag, hex(READ_FLAG_ADDR), opt_emu,
                           '-f', str(pair[1].fileno()),
                           opt_binary],
                          pass_fds=[pair[1].fileno()],
                          stdout=subprocess.DEVNULL) as p:
        pair[1].close()
        try:
            for line in f.readlines():
                line = line.rstrip('\n')
                #input()
                if line.startswith('C '):
                    line = line[2:]
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
                    line = line[2:]
                    l = 0
                    i = 2
                    while i < len(line):
                        if line[i] == '\\':
                            l += 1
                            i += 4
                        else:
                            l += 1
                            i += 1
                    if opt_verbose:
                        print('S', l)
                    pair[0].recv(l)
            pair[0].shutdown(socket.SHUT_RD)
            if p.wait(opt_timeout) == 99:
                print('Suspect: {}'.format(filename))
        except TimeoutError:
            print('Timeout: {}'.format(filename))
            try:
                p.kill()
            except:
                pass
        except:
            try:
                p.kill()
            except:
                pass

def do_task(filename):
    try:
        do_task1(filename)
    except:
        traceback.print_exc()

def main():
    global opt_binary, opt_emu, opt_timeout, opt_total_timeout, opt_verbose
    ap = argparse.ArgumentParser(description='Feed txt to a cLEMENCy binary and check if the flag is read', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Examples:
  tool/replay-txt.py -e /tmp/clemency/clemency-emu -b /tmp/287-Legitimate\ Business\ Syndicate-757378e8.bin /tmp/pcap/ -i 9dump
''')
    ap.add_argument('-b', '--binary', help='path to cLEMENCy binary')
    ap.add_argument('-e', '--emu', default='./clemency_emu', help='path to clemency_emu')
    ap.add_argument('-j', '--jobs', type=int, default=0, help='number of parallel workers (default: 0, the number of cores)')
    ap.add_argument('-i', '--ignore', nargs='*', default=[], help='list of filepath patterns to ignore')
    ap.add_argument('-t', '--timeout', type=float, default=0.5, help='timeout of recv/send')
    ap.add_argument('-T', '--total-timeout', type=float, default=5, help='total timeout')
    ap.add_argument('-v', '--verbose', action='store_true', help='list of patterns to ignore')
    ap.add_argument('input', nargs='*', help='')
    args = ap.parse_args()
    opt_binary = args.binary
    opt_emu = args.emu
    opt_timeout = args.timeout
    opt_total_timeout = args.total_timeout
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
