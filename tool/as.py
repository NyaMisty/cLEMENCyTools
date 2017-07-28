#!/usr/bin/env python3
import argparse, io, os, pathlib, re, sys

def error(msg, *args):
    print(msg.format(*args), file=sys.stderr)
    sys.exit(2)

CONDITION = {
    'n': 0,
    'e': 1,
    'l': 2,
    'le': 3,
    'g': 4,
    'ge': 5,
    'no': 6,
    'o': 7,
    'ns': 8,
    's': 9,
    'sl': 10,
    'sle': 11,
    'sg': 12,
    'sge': 13,
    '': 14,
}

ADJ_RB = {
    '': 0,
    'I': 1,
    'D': 2,
}

def assemble(fin, fout):
    table = {}
    with open(pathlib.Path(__file__).resolve().parent.parent / 'isa.txt') as f:
        for lineno, line in enumerate(f.readlines(), 1):
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

                if rhs in ('Adj_rB', 'Condition', 'imm', 'Location', 'mem_off', 'Memory_Flags', 'Offset', 'Reg_Count', 'UF'):
                    entry.append((l, rhs))
                elif rhs.startswith('r'):
                    entry.append((l, 'r'))
                elif rhs.startswith('0x'):
                    entry.append((l, int(rhs, 16)))
                elif rhs.startswith('0x'):
                    entry.append((l, int(rhs, 16)))
                else:
                    error('{}: unknown recognized rhs `{}`', lineno, rhs)
                table[inst.upper()] = entry

    buf = bytearray()
    for lineno, line in enumerate(fin.readlines(), 1):
        line = line.strip()
        if not line: continue
        m = re.match(r'^(\w+):$', line)
        if m:
            label = m.group(1)
        else:
            if ' ' in line:
                inst, rest = line.split(' ', 1)
            else:
                inst, rest = line, ''
            inst = inst.upper()
            uf = False
            if inst.endswith('.'):
                uf = True
                inst = inst[:-1]
            for i in ['BR', 'B', 'CR', 'C']:
                if inst.startswith(i):
                    cc = inst[len(i):].lower()
                    inst = i
                    if cc not in CONDITION:
                        error('{}: unknown condition code `{}`', lineno, cc)
                    break
            for i in ['LDS', 'LDT', 'LDW', 'STS', 'STT', 'STW']:
                if inst.startswith(i):
                    adj_rb = inst[len(i):].lower()
                    inst = i
                    if adj_rb not in ADJ_RB:
                        error('{}: unknown Adj_rB suffix `{}`', lineno, adj_rb)
                    m = re.match(r'(r\d+),\[(r\d+)\+(\d+),(\d+)\]', rest.replace(' ', ''))
                    if not m:
                        error('{}: {} invalid operands', lineno, inst)
                    ops = [m.group(1), m.group(2), m.group(4), m.group(3)]
                    break
            else:
                ops = [i.strip() for i in rest.split(',')]
            if inst not in table:
                error('Unknown instruction `{}`'.format(inst))

            entry = table[inst]
            x = n = 0
            # most instructions

            nth = 0
            for l, i in entry:
                if i in ('imm', 'Location', 'mem_off', 'Memory_Flags', 'Reg_Count'):
                    nth += 1
                    if not ops:
                        error('{}: instruction `{}`: missing operand {}', lineno, inst, nth)
                    try:
                        x = x << l | int(ops.pop(0), 0)
                    except ValueError:
                        error('{}: invalid immediate number', lineno)
                elif i == 'Adj_rB':
                    x = x << l | ADJ_RB[adj_rb]
                elif i == 'Condition':
                    x = x << l | CONDITION[cc]
                elif i == 'r':
                    nth += 1
                    if not ops:
                        error('{}: instruction `{}`: missing operand {}', lineno, inst, nth)
                    t = ops.pop(0)
                    m = re.match(r'r(\d+)$', t, re.I)
                    if not m:
                        error('{}: register operand', lineno)
                    x = x << l | int(m.group(1))
                elif i == 'Offset':
                    nth += 1
                    # TODO(label)
                    x = x << l | int(ops.pop(0))
                elif i == 'UF':
                    x = x << l | (1 if uf else 0)
                    uf = False
                elif isinstance(i, int):
                    x = x << l | i
                else:
                    error('{}: unknown recognized `{}`', lineno, i)
                n += l
            while n >= 8:
                buf.append(x >> n-8)
                x &= (1 << n-8) - 1
                n -= 8
            if uf:
                error('{}: `{}` does not have UF', lineno, inst)
    if n > 0:
        buf.append(x << 8-n)
    fout.write(bytes(buf))

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
        if args.asm_file == '-':
            error('Please specify -o when using - as input')
    with open(args.output, 'wb') as fout:
        if args.asm_file == '-':
            assemble(sys.stdin, fout)
        else:
            with open(args.asm_file, 'rb') as fin:
                assemble(fin, fout)

if __name__ == '__main__':
    main()
