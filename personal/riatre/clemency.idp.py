# coding=utf-8

from idaapi import *
from idc import *
from constants import *
import idautils
import copy
import ctypes

class InvalidInstructionError(Exception):
    pass

class DecodingError(Exception):
    pass

def ToSignedInteger(x, bw):
    return x - (1 << bw) if x & (1 << (bw - 1)) else x

def MiddleEndianToBigEndian(bits):
    return bits[9:18]+bits[0:9]+bits[18:27]

EA_BITMASK = 0x7ffffff

FL_B = 0x000000001  # 8 bits
FL_W = 0x000000002  # 16 bits
FL_D = 0x000000004  # 32 bits
FL_Q = 0x000000008  # 64 bits
FL_OP1 = 0x000000010  # check operand 1
FL_32 = 0x000000020  # Is 32
FL_64 = 0x000000040  # Is 64
FL_NATIVE = 0x000000080  # native call (not EbcCal)
FL_REL = 0x000000100  # relative address
FL_CS = 0x000000200  # Condition flag is set
FL_NCS = 0x000000400  # Condition flag is not set
FL_INDIRECT = 0x000000800  # This is an indirect access (not immediate value)
FL_SIGNED = 0x000001000  # This is a signed operand
FL_MULTIREG = 0x000002000

PRFL_NOUF = 0x1

FL_ABSOLUTE = 1  # absolute: &addr
FL_SYMBOLIC = 2  # symbolic: addr

o_regset = o_idpspec1
o_cc = o_idpspec5

PR_TINFO = 0x20000000  # not present in python??

class openrisc_processor_hook_t(IDP_Hooks):
    def __init__(self):
        IDP_Hooks.__init__(self)

    def decorate_name3(self, name, mangle, cc):
        gen_decorate_name3(name, mangle, cc)
        return name

    def calc_retloc3(self, rettype, cc, retloc):
        if not rettype.is_void():
            retloc._set_reg1(10)
        return 1

    def calc_varglocs3(self, ftd, regs, stkargs, nfixed):
        return 1

    def calc_arglocs3(self, fti):
        self.calc_retloc3(fti.rettype, 0, fti.retloc)
        n = fti.size()
        for i in xrange(0, n):
            if i > 7:
                return -1
            fti[i].argloc.set_reg1(10 + i, 0)
        fti.stkargs = 0
        return 2

    def use_stkarg_type3(self, ea, arg):
        return 0

    def use_arg_types3(self, ea, fti, rargs):
        gen_use_arg_tinfos(ea, fti, rargs)
        return 2

    def calc_purged_bytes3(self, p_purged_bytes, fti):
        p_purged_bytes = 0
        return 2


class ClemencyProcessor(processor_t):
    # id = 0x8001 + 0x5571C
    id = 243
    # flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_TINFO | PR_TYPEINFO
    flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 9
    dnbits = 9
    author = "Tea Deliverers"
    psnames = ["cLEMENCy"]
    plnames = ["cLEMENCy"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR,
        "uflag": 0,
        "name": "cLEMENCy architecture",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
        "a_dword": ".dword",
        "a_qword": ".qword",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",
    }

    # 在这里填上寄存器的顺序
    # 记得也要留着下面的两行哦
    # virtual
    reg_names = regNames = ["R%d" % i for i in range(29)] + 
                           ["ST", "RA", "PC", "FL"] + ["CS", "DS"]

    # {'name': 'lui', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'lui rd,imm'},
    # 在这里按照上面的格式添加指令~~
    instruc = instrs = [
        {'name': 'ad', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'AD RA, RB, RC'},
        {'name': 'adc', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADC RA, RB, RC + Carray_Bit'},
        {'name': 'adci', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADCI RA, RB, IMM'},
        {'name': 'adcim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADCIM RA, RB, IMM (54bit-reg'},
        {'name': 'adcm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra:ra+1 <- rb:rb+1 + rc:rc+1 + C_B'},
        {'name': 'adf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'add float num'},
        {'name': 'adfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': '54bit float number add(ra:ra+1 <- rb:rb+1 + rc:rc+1)'},
        {'name': 'adi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra <- rb + imm'},
        {'name': 'adim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': ''},
        {'name': 'adm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': ''},
        {'name': 'an', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra <- rb & rc'},
        {'name': 'ani', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra <- rb & imm'},
        {'name': 'anm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra:ra+1 <- rb:rb+1 & rc:rc+1'},
        {'name': 'bn', 'feature': CF_JUMP | CF_USE1, 'cmt': 'NOT ZERO'},
        {'name': 'be', 'feature': CF_JUMP | CF_USE1, 'cmt': 'zero'},
        {'name': 'bl', 'feature': CF_JUMP | CF_USE1, 'cmt': 'LESS THAN'},
        {'name': 'ble', 'feature': CF_JUMP | CF_USE1, 'cmt': '<='},
        {'name': 'bg', 'feature': CF_JUMP | CF_USE1, 'cmt': '>'},
        {'name': 'bge', 'feature': CF_JUMP | CF_USE1, 'cmt': '>='},
        {'name': 'bno', 'feature': CF_JUMP | CF_USE1, 'cmt': 'not overflow'},
        {'name': 'bo', 'feature': CF_JUMP | CF_USE1, 'cmt': 'overflow'},
        {'name': 'bns', 'feature': CF_JUMP | CF_USE1, 'cmt': 'not signed'},
        {'name': 'bs', 'feature': CF_JUMP | CF_USE1, 'cmt': 'signed'},
        {'name': 'bsl', 'feature': CF_JUMP | CF_USE1, 'cmt': 'signed <'},
        {'name': 'bsle', 'feature': CF_JUMP | CF_USE1, 'cmt': 'signed <='},
        {'name': 'bsg', 'feature': CF_JUMP | CF_USE1, 'cmt': 'signed >'},
        {'name': 'bsge', 'feature': CF_JUMP | CF_USE1, 'cmt': 'signed >='},
        {'name': 'b', 'feature': CF_JUMP | CF_USE1 | CF_STOP, 'cmt': 'ALWAYS'},
        {'name': 'bf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'RA <- ~Rb'},
        {'name': 'bfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'RA:RA+1 <- ~RB:RB+1'},
        {'name': 'br', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'always'},
        {'name': 'brn', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'not zero'},
        {'name': 'brl', 'feature': CF_USE1 | CF_JUMP, 'cmt': '<'},
        {'name': 'brle', 'feature': CF_USE1 | CF_JUMP, 'cmt': '<='},
        {'name': 'brg', 'feature': CF_USE1 | CF_JUMP, 'cmt': '>'},
        {'name': 'brge', 'feature': CF_USE1 | CF_JUMP, 'cmt': '>='},
        {'name': 'brno', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'not overflow'},
        {'name': 'bro', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'verflow'},
        {'name': 'brns', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'not signed'},
        {'name': 'brs', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'signed'},
        {'name': 'brsl', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'signed <'},
        {'name': 'brsle', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'signed <='},
        {'name': 'brsg', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'signed >'},
        {'name': 'brsge', 'feature': CF_USE1 | CF_JUMP, 'cmt': 'signed >='},
        {'name': 'bra', 'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': ''},
        {'name': 'brr', 'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': ''},
        ##############
        {'name': 'c', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Always'},
        {'name': 'cn', 'feature': CF_CALL | CF_USE1, 'cmt': ' not zero'},
        {'name': 'ce', 'feature': CF_CALL | CF_USE1, 'cmt': 'zero'},
        {'name': 'cl', 'feature': CF_CALL | CF_USE1, 'cmt': '<'},
        {'name': 'cle', 'feature': CF_CALL | CF_USE1, 'cmt': '<='},
        {'name': 'cg', 'feature': CF_CALL | CF_USE1, 'cmt': '>'},
        {'name': 'cge', 'feature': CF_CALL | CF_USE1, 'cmt': '>='},
        {'name': 'cno', 'feature': CF_CALL | CF_USE1, 'cmt': 'not overflow'},
        {'name': 'co', 'feature': CF_CALL | CF_USE1, 'cmt': 'overflow'},
        {'name': 'cns', 'feature': CF_CALL | CF_USE1, 'cmt': 'not signed'},
        {'name': 'cs', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed'},
        {'name': 'csl', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed <'},
        {'name': 'csle', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed <='},
        {'name': 'csg', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed >'},
        {'name': 'cge', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed >='},
        {'name': 'caa', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Absolute   RA=PC+4 pc = location'},
        {'name': 'car', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Relative   CAR Offset'},
        {'name': 'cm', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare  CM rA, rB'},
        {'name': 'cmf', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Floating Point  CMF rA, rB'},
        {'name': 'cmfm', 'feature': CF_USE1 | CF_USE2,'cmt': 'Compare Floating Point Multi Reg CMFM rA, rB'},
        {'name': 'cmi', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Immediate   CMI rA, IMM'},
        {'name': 'cmim', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Immediate Multi Reg  CMIM rA, IMM(ra:ra+1)'},
        {'name': 'cmm', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Multi Reg   CMM rA, rB'},
        #
        {'name': 'cr', 'feature': CF_USE1 | CF_CALL, 'cmt': 'Call Register Conditional Always    CRcc rA'},
        {'name': 'crn', 'feature': CF_USE1 | CF_CALL, 'cmt': 'not zero'},
        {'name': 'cre', 'feature': CF_USE1 | CF_CALL, 'cmt': 'zero'},
        {'name': 'crl', 'feature': CF_USE1 | CF_CALL, 'cmt': '<'},
        {'name': 'crle', 'feature': CF_USE1 | CF_CALL, 'cmt': '<='},
        {'name': 'crg', 'feature': CF_USE1 | CF_CALL, 'cmt': '>'},
        {'name': 'crge', 'feature': CF_USE1 | CF_CALL, 'cmt': '>='},
        {'name': 'crno', 'feature': CF_USE1 | CF_CALL, 'cmt': 'not overflow'},
        {'name': 'cro', 'feature': CF_USE1 | CF_CALL, 'cmt': 'overfow'},
        {'name': 'crns', 'feature': CF_USE1 | CF_CALL, 'cmt': 'not signed'},
        {'name': 'crs', 'feature': CF_USE1 | CF_CALL, 'cmt': 'signed'},
        {'name': 'crsl', 'feature': CF_USE1 | CF_CALL, 'cmt': 's <'},
        {'name': 'crsle', 'feature': CF_USE1 | CF_CALL, 'cmt': 's <='},
        {'name': 'crsg', 'feature': CF_USE1 | CF_CALL, 'cmt': 's >'},
        {'name': 'crsge', 'feature': CF_USE1 | CF_CALL, 'cmt': 's >='},
        #
        {'name': 'dbrk', 'feature': CF_STOP, 'cmt': 'Debug Break    DBRK'},
        {'name': 'di', 'feature': CF_USE1 , 'cmt': 'Disable Interrupts   DI rA'},
        {'name': 'dmt', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'copy data from [rb + p] to [ra + p] for rc times  DMT rA, rB, rC'},
        {'name': 'dv', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide   DV rA, rB, rC'},
        {'name': 'dvf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Floating Point   DVF rA, rB, rC'},
        {'name': 'dvfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3| CF_CHG1,'cmt': 'Divide Floating Point Multi Reg    DVFM rA, rB, rC'},
        {'name': 'dvi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 |CF_CHG1, 'cmt': 'Divide Immediate    DVI rA, rB, IMM'},
        {'name': 'dvim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Divide Immediate Multi Reg DVIM rA, rB, IMM'},
        {'name': 'dvis', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Immediate Signed    DVIS rA, rB, IMM'},
        {'name': 'dvism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Divide Immediate Signed Multi Reg  DVISM rA, rB, IMM'},
        {'name': 'dvm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Multi Reg    DVM rA, rB, rC'},
        {'name': 'dvs', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Signed   DVS rA, rB, rC'},
        {'name': 'dvsm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Signed Multi Reg    DVSM rA, rB, rC'},
        {'name': 'ei', 'feature': CF_USE1 , 'cmt': 'Enable Interrupts    EI rA'},
        #
        {'name': 'fti', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer ra <- (int)rb ;FTI rA, rB'},
        {'name': 'ftim', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer Multi Reg FTIM rA, rB'},
        {'name': 'ht', 'feature': CF_STOP, 'cmt': 'Halt HT'},
        {'name': 'ir', 'feature': CF_STOP, 'cmt': 'Interrupt Return IR'},
        {'name': 'itf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float    ITF rA, rB'},
        {'name': 'itfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float Multi Reg ITFM rA, rB'},
        #load
        {'name': 'lds', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Load Single    LDSm rA, [rB + Offset, RegCount]'},
        {'name': 'ldt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Load Tri    LDTm rA, [rB + Offset, RegCount]'},
        {'name': 'ldw', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Load Word   LDWm rA, [rB + Offset, RegCount]'},
        #
        {'name': 'md', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus  MD rA, rB, rC'},
        {'name': 'mdf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Floating Point  MDF rA, rB, rC'},
        {'name': 'mdfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Modulus Floating Point Multi Reg   MDFM rA, rB, rC'},
        {'name': 'mdi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Immediate   MDI rA, rB, IMM'},
        {'name': 'mdim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Modulus Immediate Multi Reg    MDIM rA, rB, IMM'},
        {'name': 'mdis', 'feature': CF_USE1 | CF_USE2 | CF_USE3 |CF_CHG1, 'cmt': 'Modulus Immediate Signed   MDIS rA, rB, IMM'},
        {'name': 'mdism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Immediate Signed Multi Reg MDISM rA, rB, IMM'},
        {'name': 'mdm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Multi Reg   MDM rA, rB, rC'},
        {'name': 'mds', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Signed  MDS rA, rB, rC'},
        {'name': 'mdsm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Signed Multi Reg   MDSM rA, rB, rC'},
        
        #
        {'name': 'mh', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move High    MH rA, IMM'},
        {'name': 'ml', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low ML rA, IMM'},
        {'name': 'ms', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low Signed  MS rA, IMM'},
        {'name': 'mu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply MU rA, rB, rC'},
        {'name': 'muf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Floating Point MUF rA, rB, rC'},
        {'name': 'mufm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Multiply Floating Point Multi Reg  MUFM rA, rB, rC'},
        {'name': 'mui', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Immediate  MUI rA, rB, IMM'},
        {'name': 'muim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Multiply Immediate Multi Reg   MUIM rA, rB, IMM'},
        {'name': 'muis', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Multiply Immediate Signed  MUIS rA, rB, IMM'},
        {'name': 'muism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Multiply Immediate Signed Multi Reg    MUISM rA, rB, IMM'},
        {'name': 'mum', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Multi Reg  MUM rA, rB, rC'},
        {'name': 'mus', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Signed MUS rA, rB, rC'},
        {'name': 'musm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Signed Multi Reg  MUSM rA, rB, rC'},
        #
        {'name': 'ng', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate   NG rA, rB'},
        {'name': 'ngf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Floating Point   NGF rA, rB'},
        {'name': 'ngfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,'cmt': 'Negate Floating Point Multi Reg    NGFM rA, rB'},
        {'name': 'ngm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Multi Reg    NGM rA, rB'},
        {'name': 'nt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not  NT rA, rB'},
        {'name': 'ntm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not Multi Reg   NTM rA, rB'},
        #or
        {'name': 'or', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or   OR rA, rB, rC'},
        {'name': 'ori', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or Immediate    ORI rA, rB, IMM'},
        {'name': 'orm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or Multi Reg    ORM rA, rB, rC'},
        {'name': 're', 'feature': CF_STOP , 'cmt': 'Return   RE'},
        {'name': 'rf', 'feature': CF_USE1 | CF_STOP | CF_CHG1, 'cmt': 'Read Flags   RF rA'},
        {'name': 'rl', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Left  RL rA, rB, rC'},
        {'name': 'rli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Left Immediate   RLI rA, rB, IMM'},
        {'name': 'rlim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Rotate Left Immediate Multi Reg    RLIM rA, rB, IMM'},
        {'name': 'rlm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Left Multi Reg   RLM rA, rB, rC'},
        {'name': 'rmp', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Read Memory Protection  RMP rA, rB'},
        {'name': 'rnd', 'feature': CF_USE1 | CF_CHG1, 'cmt': 'Random  RND rA'},
        {'name': 'rndm', 'feature': CF_USE1 | CF_CHG1, 'cmt': 'Random Multi Reg   RNDM rA'},
        {'name': 'rr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Right RR rA, rB, rC'},
        {'name': 'rri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Right Immediate  RRI rA, rB, IMM'},
        {'name': 'rrim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Rotate Right Immediate Multi Reg   RRIM rA, rB, rC'},
        {'name': 'rrm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Right Multi Reg  RRM rA, rB, rC'},
        {'name': 'sa', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Arithemetic Right  SA rA, rB, rC'},
        {'name': 'sai', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Shift Arithemetic Right Immediate  SAI rA, rB, IMM'},
        {'name': 'saim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Shift Arithemetic Right Immediate Multi Reg    SAIM rA, rB, IMM'},
        {'name': 'sam', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Shift Arithemetic Right Multi Reg  SAM rA, rB, rC'},
        {'name': 'sb', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract SB rA, rB, rC'},
        {'name': 'sbc', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract With Carry SBC rA, rB, rC'},
        {'name': 'sbci', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Subtract Immediate With Carry  SBCI rA, rB, IMM'},
        {'name': 'sbcim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Subtract Immediate Multi Reg With Carry    SBCIM rA, rB, IMM'},
        {'name': 'sbcm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Subtract Multi Reg With Carry  SBCM rA, rB, rC'},
        {'name': 'sbf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract Floating Point SBF rA, rB, rC'},
        {'name': 'sbfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Subtract Floating Point Multi Reg  SBFM rA, rB, rC'},
        {'name': 'sbi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract Immediate  SBI rA, rB, IMM'},
        {'name': 'sbim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Subtract Immediate Multi Reg   SBIM rA, rB, IMM'},
        {'name': 'sbm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract Multi Reg  SBM rA, rB, rC'},
        {'name': 'ses', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Sign Extend Single  SES rA, rB'},
        {'name': 'sew', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Sign Extend Word    SEW rA, rB'},
        {'name': 'sf', 'feature': CF_USE1 | CF_USE2 , 'cmt': 'Set Flags    SF rA'},
        {'name': 'sl', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Shift Left   SL rA, rB, rC'},
        {'name': 'sli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Left Immediate    SLI rA, rB, IMM'},
        {'name': 'slim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Shift Left Immediate Multi Reg SLIM rA, rB, IMM'},
        {'name': 'slm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Left Multi Reg    SLM rA, rB, rC'},
        {'name': 'smp', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 , 'cmt': 'Set Memory Protection   SMP rA, rB, FLAGS'},
        {'name': 'sr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Right  SR rA, rB, rC'},
        {'name': 'sri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Right Immediate   SRI rA, rB, IMM'},
        {'name': 'srim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,'cmt': 'Shift Right Immediate Multi Reg    SRIM rA, rB, IMM'},
        {'name': 'srm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Right Multi Reg   SRM rA, rB, rC'},
        #
        {'name': 'sts', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,'cmt': 'Store Single   STSm rA, [rB + Offset, RegCount]'},
        {'name': 'stt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Store Tri   STTm rA, [rB + Offset, RegCount]'},
        {'name': 'stw', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,'cmt': 'Store Word STWm rA, [rB + Offset, RegCount]'},
        #
        {'name': 'wt', 'feature': 0, 'cmt': 'Wait WT'},
        {'name': 'xr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor  XR rA, rB, rC'},
        {'name': 'xri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor Immediate   XRI rA, rB, IMM'},
        {'name': 'xrm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor Multi Reg   XRM rA, rB, rC'},
        {'name': 'zes', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Zero Extend Single  ZES rA, rB'},
        {'name': 'zew', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Zero Extend Word    ZEW rA, rB'}       
    ]

    instruc_end = len(instruc)
    idphook = None

    def __init__(self):
        super(ClemencyProcessor, self).__init__(self)
        self._init_instructions()
        self._init_registers()
        self.last_ml_array = [{'reg': -1, 'value': 0}]
        self.last_mh_array = [{'reg': -1, 'value': 0}]

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
        self.regFirstSreg = self.regCodeSreg = self.reg_ids["CS"]
        self.regLastSreg = self.regDataSreg = self.reg_ids["DS"]

    #
    # Read a 9-bit byte
    #
    #
    def _read_cmd_byte(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_full_byte(ea)
        self.cmd.size += 1
        return dword & 0x1ff

    def _read_cmd_byte_bitstr(self):
        cur = bitstring.BitArray(length=9)
        cur.uint = self._read_cmd_byte()
        return cur

    def _read_cmd_word_bitstr(self):
        word = bitstring.BitArray()
        for i in xrange(3):
            word += _read_cmd_byte_bitstr()
        return MiddleEndianToBigEndian(word)

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_word_bitstr()
        print opcode
        for rins in ISA_DEF:
            if opcode[:rins.opcode_bits].uint == rins.opcode and
               (rins.subopcode is None or opcode[rins.subopcode_start:rins.subopcode_start+rins.subopcode_width].uint == rins.subopcode):
                break
        else:
            raise DecodingError()

        cmd.itype = self.inames[rins.name]
        opcode_size = rins.size_in_bytes
        self.cmd.size = opcode_size
        if opcode_size == 4:
            opcode += self._read_cmd_byte_bitstr()
        elif opcode_size > 4: # at max 6
            opcode += self._read_cmd_word_bitstr()
        if rins.update_flag is not None:
            if opcode[rins.update_flag:rins.update_flag].uint == 0:
                cmd.auxpref |= PRFL_NOUF

        # This is kinda dirty...
        def ParseLoadStore():
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = ToSignedInteger(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword

        OverrideLDS = OverrideLDT = OverrideLDW = ParseLoadStore
        OverrideSTS = OverrideSTT = OverrideSTW = ParseLoadStore
        override_func_name = 'Override' + rins.name.upper()
        if override_func_name in locals():
            locals()[override_func_name]()
        else:
            for idx, oper in enumerate(rins.operands):
                val = opcode[oper.start:oper.start+oper.width].uint
                if oper.name.startswith('R') and oper.name[1] in 'ABC':
                    cmd[idx].type = o_reg
                    cmd[idx].reg = val
                    if "Multi Reg" in self.instrs[cmd.itype]['cmt']:
                        cmd[idx].specval |= FL_MULTIREG
                elif oper.name == 'imm':
                    cmd[idx].type = o_imm
                    cmd[idx].value = val
                elif oper.name == 'immS': # Signed Immediate
                    cmd[idx].type = o_imm
                    cmd[idx].value = ToSignedInteger(val, oper.width)
                elif oper.name == 'Location':
                    cmd[idx].type = o_near
                    cmd[idx].addr = val
                elif oper.name == 'Offset':
                    cmd[idx].type = o_near
                    cmd[idx].addr = cmd.ea + ToSignedInteger(val, oper.width)
                elif oper.name == 'Condition':
                    cmd[idx].type = o_cc
                    cmd[idx].specval = val # Condition code
                    cmd[idx].clr_shown()
                    newname = rins.name + CONDSUFFIX[val]
                    cmd.itype = self.inames[newname]
                else:
                    raise NotImplementedError('Instruction {1} needs custom handler for its operands {2} but not implemented!'.format(rins.name, oper.name))
                cmd[idx].dtyp = dt_dword

        return opcode_size

    def ana(self):
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _emu_operand(self, op):
        if op.type == o_mem:
            ua_dodata2(0, op.addr, op.dtyp)
            ua_add_dref(0, op.addr, dr_R)
        elif op.type == o_near:
            if self.cmd.get_canon_feature() & CF_CALL:
                fl = fl_CN
            else:
                fl = fl_JN
            ua_add_cref(0, op.addr, fl)

    #这三个是下面simplify的辅助函数可以看看供为参考
    def remove_ml_array_object(self, reg):
        ret = None
        # print "remove_lui_array_object: %s" % (self.regNames[reg])
        for idx, lui_record in enumerate(self.last_ml_array):
            if lui_record is None:
                continue
            if lui_record["reg"] is None:
                del self.last_ml_array[idx]
            elif lui_record["reg"] == reg:
                ret = copy.deepcopy(lui_record)
                del self.last_ml_array[idx]
        return ret

    def get_ml_array_object(self, reg):
        ret = None
        # print "get_lui_array_object: %s" % (self.regNames[reg])
        for idx, mh_record in enumerate(self.last_ml_array):
            if mh_record is None:
                continue
            if mh_record["reg"] is None:
                del self.last_ml_array[idx]
            elif mh_record["reg"] == reg:
                ret = mh_record
        return ret

    def remove_mh_array_object(self, reg):
        ret = None
        # print "remove_lui_array_object: %s" % (self.regNames[reg])
        for idx, lui_record in enumerate(self.last_mh_array):
            if lui_record is None:
                continue
            if lui_record["reg"] is None:
                del self.last_mh_array[idx]
            elif lui_record["reg"] == reg:
                ret = copy.deepcopy(lui_record)
                del self.last_mh_array[idx]
        return ret

    def get_mh_array_object(self, reg):
        ret = None
        # print "get_lui_array_object: %s" % (self.regNames[reg])
        for idx, mh_record in enumerate(self.last_mh_array):
            if mh_record is None:
                continue
            if mh_record["reg"] is None:
                del self.last_mh_array[idx]
            elif mh_record["reg"] == reg:
                ret = mh_record
        return ret

    def add_auto_resolved_address_comment(self, resolved_offset):
        buf = init_output_buffer(1024)
        r = out_name_expr(self.cmd, resolved_offset, BADADDR)
        if not r:
            OutLong(toInt(resolved_offset) & EA_BITMASK, 16)
        term_output_buffer()
        MakeComm(self.cmd.ea, buf)
        nn = netnode("$ simplified_addr",0,True)
        nn.altset(self.cmd.ea,resolved_offset & EA_BITMASK)
        pass

    def add_auto_resolved_constant_comment(self, resolved_offset):
        buf = init_output_buffer(1024)
        r = out_name_expr(self.cmd, resolved_offset, BADADDR)
        if not r:
            OutLong(toInt(resolved_offset) & EA_BITMASK, 16)
        term_output_buffer()
        MakeComm(self.cmd.ea, buf)
        nn = netnode("$ simplified_const", 0, True)
        nn.altset(self.cmd.ea, resolved_offset & EA_BITMASK)
        pass

    # lui            a0, 65536
    # addi           a0, a0, 320
    # add data and far call offset
    #这里是简单的化简 供参考用
    def simplify(self):
        if self.cmd.itype == self.inames['ml'] or self.cmd.itype == self.inames['ms']:
            # print "ml/md at: %08X on reg %s value %Xh\n" % (self.cmd.ea, self.regNames[self.cmd[0].reg], self.cmd[1].value)
            self.remove_ml_array_object(self.cmd[0].reg)
            self.last_ml_array.append({"reg": self.cmd[0].reg, "value": self.cmd[1].value})
            return
        if self.cmd.itype == self.inames['mh']:
            # print "mh at: %08X on reg %s value %Xh\n" % (self.cmd.ea, self.regNames[self.cmd[0].reg], self.cmd[1].value)
            self.last_mh_array.append({"reg": self.cmd[0].reg, "value": self.cmd[1].value})
        if self.cmd.itype == self.inames['lds'] or self.cmd.itype == self.inames['ldt'] \
                or self.cmd.itype == self.inames['ldw'] or self.cmd.itype == self.inames['sts'] \
                or self.cmd.itype == self.inames['stt'] or self.cmd.itype == self.inames['stw']:
            last_record_ml = self.get_ml_array_object(self.cmd[1].reg)
            self.remove_ml_array_object(self.cmd[0].reg)
            if last_record_ml != None:
                target_offset = toInt((last_record_ml["value"]) + self.cmd[1].addr)
                if (isLoaded(target_offset)):
                    ua_add_dref(0, target_offset, dr_R)
                self.add_auto_resolved_constant_comment(target_offset)
            last_record_mh = self.get_mh_array_object(self.cmd[1].reg)
            self.remove_mh_array_object(self.cmd[0].reg)
            if last_record_mh != None:
                target_offset = toInt((last_record_mh["value"] << 10) + self.cmd[1].addr)
                if (isLoaded(target_offset)):
                    ua_add_dref(0, target_offset, dr_R)
                self.add_auto_resolved_constant_comment(target_offset)
        else:
            cmd = self.cmd
            ft = cmd.get_canon_feature()
            if ft & CF_CHG1:
                last_record_ml = self.remove_ml_array_object(self.cmd[0].reg)
                self.remove_mh_array_object(self.cmd[0].reg)
                # print last_record_ml
                if last_record_ml != None:
                    # print "trying to match addi or jalr for lui, cur ea: %08X" % (self.cmd.ea)
                    if self.cmd.itype == self.inames['mh']:
                        target_offset = toInt((last_record_ml["value"]) + (self.cmd[1].value << 10))
                        if (isLoaded(target_offset)):
                            ua_add_dref(0, target_offset, dr_R)
                        self.add_auto_resolved_constant_comment(target_offset)

    #这个函数不用动哒
    def add_stkpnt(self, pfn, v):
        if pfn:
            end = self.cmd.ea + self.cmd.size
            if not is_fixed_spd(end):
                AddAutoStkPnt2(pfn, end, v)

    #这里处理会修改sp的指令，如果懒or时间不够的话就留空吧
    def trace_sp(self):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        # pfn = get_func(self.cmd.ea)
        # if not pfn:
        #    return
        """if self.cmd[0].reg != None and self.cmd[0].reg == 2 and self.cmd[1].reg != None and self.cmd[1].reg == 2 and \
                        self.cmd.itype in [self.inames['addi'], self.inames['addid'], self.inames['addiw']]:
            # print self.cmd[2].value
            spofs = toInt(self.cmd[2].value)
            # print spofs
            self.add_stkpnt(self.cmd.ea, spofs)"""
        pass

    def emu(self):
        cmd = self.cmd
        # 下面的全是套路，flow是该指令是否将控制流传给下一条相邻指令的意思
        flow = False
        # 其他指令正常处理
        ft = cmd.get_canon_feature()
        if ft & CF_USE1:
            self._emu_operand(cmd[0])
        if ft & CF_USE2:
            self._emu_operand(cmd[1])
        if ft & CF_USE3:
            self._emu_operand(cmd[2])
        if ft & CF_USE4:
            self._emu_operand(cmd[3])

        elif not ft & CF_STOP:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)
            flow = True
        self.simplify()
        # trace the stack pointer if:
        #   - it is the second analysis pass
        #   - the stack pointer tracing is allowed
        if may_trace_sp():
            if flow:
                self.trace_sp()  # trace modification of SP register
            else:
                recalc_spd(self.cmd.ea)  # recalculate SP register for the next insn
        return True

    # 剩下的这两个函数全是基本固定的 等出问题再说
    def outop(self, op):
        optype = op.type
        fl = op.specval

        if optype == o_reg:
            out_register(self.regNames[op.reg])

        elif optype == o_imm:
            OutValue(op, OOFW_IMM | OOFW_32 | OOF_SIGNED)

        elif optype in [o_near, o_mem]:
            if optype == o_mem and fl == FL_ABSOLUTE:
                out_symbol('&')
            r = out_name_expr(op, op.addr, BADADDR)
            if not r:
                out_tagon(COLOR_ERROR)
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueSet(Q_noName, self.cmd.ea)
                # OutLong(op.addr, 16)

        elif optype == o_regset:
            out_register(self.regNames[op.reg])
            if op.value > 0:
                out_symbol('-')
                out_register(self.regNames[op.reg+op.value])

        elif optype == o_displ:
            if fl & FL_INDIRECT:
                out_symbol('[')
            out_register(self.regNames[op.reg])

            OutValue(op, OOF_ADDR | OOFW_32 | OOFS_NEEDSIGN | OOF_SIGNED)

            if fl & FL_INDIRECT:
                out_symbol(']')

        elif optype == o_phrase:
            out_symbol('@')
            out_register(self.regNames[op.reg])
        else:
            return False

        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        if cmd.auxpref & PRFL_NOUF:
            OutMnem(15, ".nf")
        else:
            OutMnem(15)
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

    def notify_init(self,idp_file):
        try:
            idp_hook_stat = "un"
            print "IDP hook: checking for hook..."
            self.idphook
            print "IDP hook: unhooking...."
            self.idphook.unhook()
            self.idphook = None
        except:
            print "IDP hook: not installed, installing now...."
            idp_hook_stat = ""
            self.idphook = openrisc_processor_hook_t()
            self.idphook.hook()
        #cvar.inf.mf = LITTLE_ENDIAN
        return True

    def notify_term(self):
        try:
            idp_hook_stat = "un"
            print "IDP hook: checking for hook..."
            self.idphook
            print "IDP hook: unhooking...."
            self.idphook.unhook()
            self.idphook = None
        except:
            pass

def PROCESSOR_ENTRY():
    return ClemencyProcessor()
