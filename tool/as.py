#!/usr/bin/env python3
import argparse, os, pathlib, re, sys

def error(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)

def assemble(fin, fout):
    table = {}
    with open(pathlib.Path(__file__).resolve().parent.parent / 'isa.txt') as f:
        for line in f.readlines():
            inst, *fields, _nbytes = line.rstrip('\n').split()
            entry = []
            for field in fields:
                bits, rhs = field.split('=')
                bits = list(map(int, bits.split('-')))
                if len(bits) == 1:
                    l = 1
                else:
                    l = bits[1]-bits[0]+1
                # register
                if rhs.startswith('r'):
                    entry.append((l, 'r'))
                elif rhs.startswith('0x'):
                    entry.append((l, int(rhs, 16)))
                elif rhs.startswith('0x'):
                    entry.append((l, int(rhs, 16)))
                elif rhs == 'UF':
                    entry.append((l, rhs))
            table[inst.upper()] = entry

    for lineno, line in enumerate(fin.readlines(), 1):
        if line.strip() == '': continue
        m = re.match(r'^(\w+):$', line)
        if m:
            # TODO label
            pass
        else:
            if ' ' in line:
                inst, rest = line.split(' ', 1)
            else:
                inst, rest = line, ''
            inst = inst.upper()
            ops = rest.split(',')
            if inst not in table:
                error('Unknown instruction `{}`'.format(inst))
            entry = table[inst]
            x = n = 0
            # most instructions

            for l, i in entry:
                if i == 'r':
                    if not ops:
                        error('Instruction `{}` has {} operand(s)'.format(inst, len(entry)))
                elif i == 'UF':
                    continue
                elif isinstance(i, int):
                    x = x << l | i
            #print('++')

def main():
    ap = argparse.ArgumentParser(description='cLEMENCy assembler', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Examples:
./as.py
./as.py
    ''')
    ap.add_argument('-o', '--output', help='output filename')
    ap.add_argument('asm_file', help='')
    args = ap.parse_args()
    if args.output is None:
        args.output = args.asm_file + '.o'
    with open(args.output, 'wb') as fout:
        if args.asm_file == '-':
            assemble(sys.stdin, fout)
        else:
            with open(args.asm_file, 'rb') as fin:
                assemble(fin, fout)

if __name__ == '__main__':
    main()
