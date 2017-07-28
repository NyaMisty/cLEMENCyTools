#!/usr/bin/env python3
import argparse, sys

def from_9_to_16(fin, fout):
    buf = bytearray()
    x = 0
    n = 0
    for i in fin.read():
        while n >= 9:
            t = x >> n-9
            x &= (1 << n-9) - 1
            # convert a 9-bit byte to 2 big-endian octets
            buf.append(t & 255)
            buf.append(t >> 8)
            n -= 9
        x = x << 8 | i
        n += 8
    while n >= 9:
        t = x >> n-9
        x &= (1 << n-9) - 1
        buf.append(t & 255)
        buf.append(t >> 8)
        n -= 9
    fout.write(bytes(buf))

def from_16_to_9(fin, fout):
    a = fin.read()
    fin.read()
    buf = bytearray()
    x = 0
    n = 0
    for i in range(0, len(a), 2):
        while n >= 8:
            buf.append(x >> n-8)
            x &= (1 << n-8) - 1
            n -= 8
        t = a[i+1] << 8 | a[i]
        assert t < 512, 'should < 512'
        x = x << 9 | t
        n += 9
    while n >= 8:
        buf.append(x >> n-8)
        x &= (1 << n-8) - 1
        n -= 8
    if n > 0:
        buf.append(x << 8-n)
    fout.write(bytes(buf))

def main():
    ap = argparse.ArgumentParser(description='convert between 9-bit cLEMENCy and 16-bit binary', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='''
Examples:
convert-bits from.9 to.16
convert-bits from.16 to.9
    ''')
    ap.add_argument('input_file', help='')
    ap.add_argument('output_file', help='')
    args = ap.parse_args()
    if args.input_file.endswith('.9'):
        if not args.output_file.endswith('.16'):
            print('output_file should end with .16', file=sys.stderr)
            sys.exit(1)
        with open(args.input_file, 'rb') as fin, open(args.output_file, 'wb') as fout:
            from_9_to_16(fin, fout)
    elif args.input_file.endswith('.16'):
        if not args.output_file.endswith('.9'):
            print('output_file should end with .9', file=sys.stderr)
            sys.exit(1)
        with open(args.input_file, 'rb') as fin, open(args.output_file, 'wb') as fout:
            from_16_to_9(fin, fout)
    else:
        print('input_file should end with .9 or .16', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
