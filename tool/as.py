#!/usr/bin/env python3
import argparse, collections, io, os, pathlib, re, sys

def error(msg, *args):
    print(msg.format(*args), file=sys.stderr)
    sys.exit(2)

def serialize_sign(l, x):
    if x >= 1 << l-1:
        error('Offset too large')
    if x < -(1 << l-1):
        error('Offset too small')
    return x if x >= 0 else (1 << l) + x

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
    '': 15,
}

ADJ_RB = {
    '': 0,
    'I': 1,
    'D': 2,
}

def assemble(fin, output, format):
    table = {}
    with open((pathlib.Path(__file__).resolve().parent.parent / 'isa.txt').as_posix()) as f:
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
                else:
                    error('{}: unknown recognized rhs `{}`', lineno, rhs)
                table[inst.upper()] = entry

    addr = opt_start
    label2addr = {}
    reloc = collections.defaultdict(list)
    code = []
    code_ends = []
    for lineno, line in enumerate(fin.readlines(), 1):
        line = line.strip()
        if not line: continue
        m = re.match(r'^(\w+):$', line)
        if m:
            label = m.group(1)
            if label in label2addr:
                error('{}: label `{}` redefined', lineno, label)
            label2addr[m.group(1)] = addr
            for (addr0, n, l, typ) in reloc[label]:
                i = n
                end = n+l
                value = addr-addr0 if typ == 'rel' else addr
                while i < end:
                    j = min(i+9-i%9, end)
                    l -= j-i
                    code[addr0+i//9] = code[addr0+i//9] & ~((1<<j-i)-1 << (9-j)%9) | (value>>l) << (9-j)%9
                    value &= (1 << l) - 1
                    i = j
            del reloc[label]
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
            # most instructions

            nth = x = n = 0
            for l, i in entry:
                if i in ('imm', 'mem_off', 'Memory_Flags', 'Reg_Count'):
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
                elif i == 'Location':
                    nth += 1
                    t = ops.pop(0)
                    try:
                        t = int(t, 0)
                    except ValueError:
                        if t in label2addr:
                            t = label2addr[t]
                        else:
                            reloc[t].append((addr-opt_start, n, l, 'abs'))
                            t = -1
                    x = x << l | serialize_sign(l, t)
                elif i == 'Offset':
                    nth += 1
                    t = ops.pop(0)
                    try:
                        t = int(t, 0)
                    except ValueError:
                        if t in label2addr:
                            t = label2addr[t]
                        else:
                            reloc[t].append((addr-opt_start, n, l, 'rel'))
                            t = -1
                    x = x << l | serialize_sign(l, t)
                elif i == 'UF':
                    x = x << l | (1 if uf else 0)
                    uf = False
                elif isinstance(i, int):
                    x = x << l | i
                else:
                    error('{}: unknown recognized `{}`', lineno, i)
                n += l

            if uf:
                error('{}: `{}` does not have UF', lineno, inst)
            assert n % 9 == 0, 'Unaligned op, please check'
            addr += n // 9
            code_ends.append(addr)
            while n >= 9:
                code.append(x >> n-9)
                x &= (1 << n-9) - 1
                n -= 9
            label = None

    if reloc:
        error('Unknown labels {}', ' '.join(reloc.keys()))

    # middle endian
    addr = 0
    for i in code_ends:
        for j in range(addr, i-1, 3):
            code[j], code[j+1] = code[j+1], code[j]
        addr = i

    if format == '9bit':
        fout = sys.stdout if output == '-' else open(output, 'w')
        for i in code:
            fout.write('{:03x} '.format(i))
        fout.close()
    elif format == 'bin':
        fout = sys.stdout if output == '-' else open(output, 'w')
        for i in code:
            fout.write('{:09b} '.format(i))
        fout.close()
    elif format == 'octet':
        n = x = 0
        buf = bytearray()
        for i in code:
            x = x << 9 | i
            n += 9
            while n >= 8:
                buf.append(x >> n-8)
                x &= (1 << n-8) - 1
                n -= 8
        if n > 0:
            buf.append(x << 8-n)
        fout = sys.stdout if output == '-' else open(output, 'wb')
        fout.write(bytes(buf))
        fout.close()

def main():
    global opt_start
    ap = argparse.ArgumentParser(description='cLEMENCy assembler', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Examples:
./as.py -f 9bit clemency.s  # 100 120 003
./as.py -f bin clemency.s  # 100000000 100100000
./as.py -f octet clemency.s -o clemency.o
    ''')
    ap.add_argument('-f', '--format', default='9bit', choices=('bin', 'octet', '9bit'), help='output format')
    ap.add_argument('-o', '--output', default='-', help='output filename')
    ap.add_argument('-s', '--start-address', type=int, default=0, help='start address')
    ap.add_argument('asm_file', help='')
    args = ap.parse_args()
    opt_start = args.start_address
    if args.asm_file == '-':
        assemble(sys.stdin, args.output, args.format)
    else:
        with open(args.asm_file, 'r') as fin:
            assemble(fin, args.output, args.format)

if __name__ == '__main__':
    main()
