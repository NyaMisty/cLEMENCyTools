instrs = [
    'ad', 'adc', 'adci', 'adcim', 'adcm', 'adf', 'adfm', 'adi', 'adim', 'adm', 'an', 'ani', 'anm', 'bn', 'be', 'bl', 'ble', 'bg', 'bge', 'bno', 'bo', 'bns', 'bs', 'bsl', 'bsle', 'bsg', 'bsge', 'b', 'bf', 'bfm', 'br', 'brn', 'brl', 'brle', 'brg', 'brge', 'brno', 'bro', 'brns', 'brs', 'brsl', 'brsle', 'brsg', 'brsge', 'bra', 'brr', ##############
    'c', 'cn', 'ce', 'cl', 'cle', 'cg', 'cge', 'cno', 'co', 'cns', 'cs', 'csl', 'csle', 'csg', 'csge', 'caa', 'car', 'cm', 'cmf', 'cmfm', 'cmi', 'cmim', 'cmm', 
    'cr', 'crn', 'cre', 'crl', 'crle', 'crg', 'crge', 'crno', 'cro', 'crns', 'crs', 'crsl', 'crsle', 'crsg', 'crsge', 
    'dbrk', 'di', 'dmt', 'dv', 'dvf', 'dvfm', 'dvi', 'dvim', 'dvis', 'dvism', 'dvm', 'dvs', 'dvsm', 'ei', 
    'fti', 'ftim', 'ht', 'ir', 'itf', 'itfm', 
    'lds', 'ldt', 'ldw', 
    'ldis', 'ldit', 'ldiw', 
    'ldds', 'lddt', 'lddw', 
    'md', 'mdf', 'mdfm', 'mdi', 'mdim', 'mdis', 'mdism', 'mdm', 'mds', 'mdsm', 
    'mh', 'ml', 'ms', 'mu', 'muf', 'mufm', 'mui', 'muim', 'muis', 'muism', 'mum', 'mus', 'musm',
    'ng', 'ngf', 'ngfm', 'ngm', 'nt', 'ntm',
    'or', 'ori', 'orm', 're', 'rf', 'rl', 'rli', 'rlim', 'rlm', 'rmp', 'rnd', 'rndm', 'rr', 'rri', 'rrim', 'rrm', 'sa', 'sai', 'saim', 'sam', 'sb', 'sbc', 'sbci', 'sbcim', 'sbcm', 'sbf', 'sbfm', 'sbi', 'sbim', 'sbm', 'ses', 'sew', 'sf', 'sl', 'sli', 'slim', 'slm', 'smp', 'sr', 'sri', 'srim', 'srm', 
    'sts', 'stt', 'stw', 
    'stds', 'stdt', 'stdw', 
    'stis', 'stit', 'stiw',
    'wt', 'xr', 'xri', 'xrm', 'zes', 'zew'
]

mnemToCmt = {}

with open('command_cmt.txt') as fp:
    for ln in fp.read().strip().split('\n'):
        mnem, cmt = ln.split(': ')
        mnemToCmt[mnem.lower()] = cmt

with open('allins.hpp.base') as fp:
    orig = fp.read()

with open('allins.hpp', 'wt') as fp:
    fp.write(orig)
    fp.write('\n')
    print >>fp, '''/*
 * cLEMENCy opcode enumeration.
 */

extern instruc_t Instructions[];

/*
 * cLEMENCy opcode list.
 */

enum
{
'''
    for i, ins in enumerate(instrs):
        print >>fp, '\tCLEMENCY_{} = {}, '.format(ins, hex(i))
    print >>fp, '};'

ccToDesc = {
    'n': 'Not Equal / Not Zero',
    'e': 'Equal / Zero',
    'l': 'Less Than',
    'le': 'Less Than or Equal',
    'g': 'Greater Than',
    'ge': 'Greater Than or Equal',
    'no': 'Not Overflow',
    'o': 'Overflow',
    'ns': 'Not Signed',
    's': 'Signed',
    'sl': 'Signed Less Than',
    'sle': 'Signed Less Than or Equal',
    'sg': 'Signed Greater Than',
    'sge': 'Signed Greater Than or Equal'
}

with open('clemency.cmt', 'wt') as fp:
    for i, ins in enumerate(instrs):
        if ins not in mnemToCmt:
            if (ins.startswith('ld') or ins.startswith('st')) and (ins[:2] + ins[3:]) in mnemToCmt:
                cmt = mnemToCmt[ins[:2]+ins[3:]] + ' (' + {'i': 'rB increasing', 'd': 'rB decreasing'}[ins[2]] + ')'
            elif ins.startswith('b') and ins[1:] in ccToDesc:
                cmt = 'Branch If ' + ccToDesc[ins[1:]]
            elif ins.startswith('br') and ins[2:] in ccToDesc:
                cmt = 'Branch Relative If ' + ccToDesc[ins[2:]]
            elif ins.startswith('c') and ins[1:] in ccToDesc:
                cmt = 'Call If ' + ccToDesc[ins[1:]]
            elif ins.startswith('cr') and ins[2:] in ccToDesc:
                cmt = 'Call Relative If ' + ccToDesc[ins[2:]]
            else:
                assert False, ins
        else:
            cmt = mnemToCmt[ins]
        print >>fp, 'CLEMENCY_{}:\t"{}"'.format(ins, cmt)
