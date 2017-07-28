# coding=utf-8

import pydevd
pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True,suspend=False,overwrite_prev_trace=True,patch_multiprocessing=True)

from idaapi import *
from idc import *
import idautils
import copy
import ctypes
import bitstring


def SIGNEXT(x, b):
    m = 1 << (b - 1)
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

def toInt(x):
    return ctypes.c_int(x & 0xffffffff).value

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
FL_MULTIREG = 0x000002000 # This is a multi reg operand

FL_ABSOLUTE = 1  # absolute: &addr
FL_SYMBOLIC = 2  # symbolic: addr

o_regset = o_idpspec1

PR_TINFO = 0x20000000  # not present in python??

class DecodingError(Exception):
    pass

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


class openrisc_processor_t(processor_t):
    # id = 0x8001 + 0x5571C
    id = 243
    #flag = PR_SEGS | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_TINFO | PR_TYPEINFO
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
        "name": "cLEMENCy asm",
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

    reg_names = regNames = [
        # 在这里填上寄存器的顺序
        # 记得也要留着下面的两行哦
        # virtual
        "R0", "R1", "R2", "R3", "R4",
        "R5", "R6", "R7", "R8", "R9",
        "R10", "R11", "R12", "R13", "R14",
        "R15", "R16", "R17", "R18", "R19",
        "R20", "R21", "R22", "R23", "R24",
        "R25", "R26", "R27", "R28", "ST",
        "RA", "PC", "FL",
        "CS", "DS"
    ]

    instruc = instrs = [
        #{'name': 'lui', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'lui rd,imm'},
        # 在这里按照上面的格式添加指令~~
        {'name': 'ad', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'AD RA, RB, RC'},
        {'name': 'adc', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 , 'cmt': 'ADC RA, RB, RC + Carray_Bit'},
        {'name': 'adci', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1 , 'cmt': 'ADCI RA, RB, IMM'},
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
        {'name': 'brn', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'not zero'},
        {'name': 'brl', 'feature': CF_USE1 | CF_JUMP , 'cmt': '<'},
        {'name': 'brle', 'feature': CF_USE1 | CF_JUMP , 'cmt': '<='},
        {'name': 'brg', 'feature': CF_USE1 | CF_JUMP , 'cmt': '>'},
        {'name': 'brge', 'feature': CF_USE1 | CF_JUMP , 'cmt': '>='},
        {'name': 'brno', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'not overflow'},
        {'name': 'bro', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'verflow'},
        {'name': 'brns', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'not signed'},
        {'name': 'brs', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'signed'},
        {'name': 'brsl', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'signed <'},
        {'name': 'brsle', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'signed <='},
        {'name': 'brsg', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'signed >'},
        {'name': 'brsge', 'feature': CF_USE1 | CF_JUMP , 'cmt': 'signed >='},
        {'name': 'bra', 'feature': CF_USE1 | CF_JUMP | CF_STOP , 'cmt': ''},
        {'name': 'brr', 'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': ''},
        ##############
        {'name': 'c', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Always'},
        {'name': 'cn', 'feature': CF_CALL | CF_USE1 , 'cmt': ' not zero'},
        {'name': 'ce', 'feature': CF_CALL | CF_USE1 , 'cmt': 'zero'},
        {'name': 'cl', 'feature': CF_CALL | CF_USE1 , 'cmt': '<'},
        {'name': 'cle', 'feature': CF_CALL | CF_USE1 , 'cmt': '<='},
        {'name': 'cg', 'feature': CF_CALL | CF_USE1 , 'cmt': '>'},
        {'name': 'cge', 'feature': CF_CALL | CF_USE1 , 'cmt': '>='},
        {'name': 'cno', 'feature': CF_CALL | CF_USE1 , 'cmt': 'not overflow'},
        {'name': 'co', 'feature': CF_CALL | CF_USE1 , 'cmt': 'overflow'},
        {'name': 'cns', 'feature': CF_CALL | CF_USE1 , 'cmt': 'not signed'},
        {'name': 'cs', 'feature': CF_CALL | CF_USE1 , 'cmt': 'signed'},
        {'name': 'csl', 'feature': CF_CALL | CF_USE1 , 'cmt': 'signed <'},
        {'name': 'csle', 'feature': CF_CALL | CF_USE1 , 'cmt': 'signed <='},
        {'name': 'csg', 'feature': CF_CALL | CF_USE1 , 'cmt': 'signed >'},
        {'name': 'cge', 'feature': CF_CALL | CF_USE1 , 'cmt': 'signed >='},
        {'name': 'caa', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Absolute   RA=PC+4 pc = location'},
        {'name': 'car', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Relative   CAR Offset'},
        {'name': 'cm', 'feature': CF_USE1 | CF_USE2 , 'cmt': 'Compare  CM rA, rB'},
        {'name': 'cmf', 'feature': CF_USE1 | CF_USE2 , 'cmt': 'Compare Floating Point  CMF rA, rB'},
        {'name': 'cmfm', 'feature': CF_USE1 | CF_USE2 ,'cmt': 'Compare Floating Point Multi Reg CMFM rA, rB'},
        {'name': 'cmi', 'feature': CF_USE1 | CF_USE2 , 'cmt': 'Compare Immediate   CMI rA, IMM'},
        {'name': 'cmim', 'feature': CF_USE1 | CF_USE2 , 'cmt': 'Compare Immediate Multi Reg  CMIM rA, IMM(ra:ra+1)'},
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
        {'name': 'dbrk', 'feature': 0, 'cmt': 'Debug Break    DBRK'},
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
        {'name': 'ht', 'feature': 0, 'cmt': 'Halt HT'},
        {'name': 'ir', 'feature': 0, 'cmt': 'Interrupt Return IR'},
        {'name': 'itf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float    ITF rA, rB'},
        {'name': 'itfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float Multi Reg ITFM rA, rB'},
        #load
        {'name': 'lds', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,'cmt': 'Load Single    LDSm rA, [rB + Offset, RegCount]'},
        {'name': 'ldt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Load Tri    LDTm rA, [rB + Offset, RegCount]'},
        {'name': 'ldw', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2, 'cmt': 'Load Word   LDWm rA, [rB + Offset, RegCount]'},

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
        processor_t.__init__(self)
        self._init_instructions()
        self._init_registers()
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
        return dword
    def convertMiddleEndian(self,bits):
        temp1 = bits[0:9]
        temp2 = bits[9:18]
        temp3 = bits[18:27]
        return temp2+temp1+temp3
    def _ana(self):
        cmd = self.cmd
        temp_opcode = bitstring.BitArray()
        temp = bitstring.BitArray(length=9)
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        opcode = self.convertMiddleEndian(temp_opcode)
        temp_opcode = bitstring.BitArray()
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        temp.uint = (self._read_cmd_byte() & 0x1ff)
        temp_opcode += temp
        opcode += self.convertMiddleEndian(temp_opcode)
        print hex(opcode.uint)

        if opcode[0:7].uint == 0x0 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["ad"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x20 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["adc"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x20 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["adci"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x22 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["adcim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x22 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["adcm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x1 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["adf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x3 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["adfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x0 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["adi"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["adim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["adm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x14 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["an"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x14 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["ani"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x16 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["anm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0xf:
            cmd.itype = self.inames["b"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x0:
            cmd.itype = self.inames["bn"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x1:
            cmd.itype = self.inames["be"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x2:
            cmd.itype = self.inames["bl"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x3:
            cmd.itype = self.inames["ble"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x4:
            cmd.itype = self.inames["bg"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x5:
            cmd.itype = self.inames["bge"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x6:
            cmd.itype = self.inames["bno"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x7:
            cmd.itype = self.inames["bo"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x8:
            cmd.itype = self.inames["bns"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0x9:
            cmd.itype = self.inames["bs"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0xa:
            cmd.itype = self.inames["bsl"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0xb:
            cmd.itype = self.inames["bsle"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0xc:
            cmd.itype = self.inames["bsg"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x30 and opcode[6:10].uint == 0xd:
            cmd.itype = self.inames["bsge"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14c and opcode[19:26].uint == 0x40:
            cmd.itype = self.inames["bf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14e and opcode[19:26].uint == 0x40:
            cmd.itype = self.inames["bfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0xf and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["br"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x0 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brn"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x1 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["bre"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x2 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x3 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brle"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x4 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brg"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x5 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brge"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x6 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brno"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x7 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["bro"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x8 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brns"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0x9 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brs"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0xa and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brsl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0xb and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brsle"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0xc and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brsg"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x32 and opcode[6:10].uint == 0xd and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["brsge"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:9].uint == 0x1c4:
            cmd.itype = self.inames["bra"]
            cmd[0].type = o_near
            cmd[0].addr = opcode[9:36].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 4
        elif opcode[0:9].uint == 0x1c0:
            cmd.itype = self.inames["brr"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[9:36].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 4
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0xf:
            cmd.itype = self.inames["c"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x0:
            cmd.itype = self.inames["cn"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x1:
            cmd.itype = self.inames["ce"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x2:
            cmd.itype = self.inames["cl"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x3:
            cmd.itype = self.inames["cle"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x4:
            cmd.itype = self.inames["cg"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x5:
            cmd.itype = self.inames["cge"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x6:
            cmd.itype = self.inames["cno"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x7:
            cmd.itype = self.inames["co"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x8:
            cmd.itype = self.inames["cns"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0x9:
            cmd.itype = self.inames["cs"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0xa:
            cmd.itype = self.inames["csl"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0xb:
            cmd.itype = self.inames["csle"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0xc:
            cmd.itype = self.inames["csg"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:6].uint == 0x35 and opcode[6:10].uint == 0xd:
            cmd.itype = self.inames["csge"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[10:27].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x1cc:
            cmd.itype = self.inames["caa"]
            cmd[0].type = o_near
            cmd[0].addr = opcode[9:36].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 4
        elif opcode[0:9].uint == 0x1c8:
            cmd.itype = self.inames["car"]
            cmd[0].type = o_near
            cmd[0].addr = cmd.ea + SIGNEXT(opcode[9:36].uint, 27)
            cmd[0].dtyp = dt_dword
            opcode_size = 4
        elif opcode[0:8].uint == 0xb8:
            cmd.itype = self.inames["cm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[13:18].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:8].uint == 0xba:
            cmd.itype = self.inames["cmf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[13:18].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:8].uint == 0xbe:
            cmd.itype = self.inames["cmfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[13:18].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:8].uint == 0xb9:
            cmd.itype = self.inames["cmi"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_imm
            cmd[1].value = opcode[13:27].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:8].uint == 0xbd:
            cmd.itype = self.inames["cmim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_imm
            cmd[1].value = opcode[13:27].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:8].uint == 0xbc:
            cmd.itype = self.inames["cmm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[8:13].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[13:18].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0xf and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["cr"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x0 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crn"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x1 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["cre"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x2 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x3 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crle"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x4 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crg"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x5 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crge"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x6 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crno"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x7 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["cro"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x8 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crns"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0x9 and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crs"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0xa and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crsl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0xb and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crsle"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0xc and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crsg"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:6].uint == 0x37 and opcode[6:10].uint == 0xd and opcode[15:18].uint == 0x0:
            cmd.itype = self.inames["crsge"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[10:15].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:18].uint == 0x3ffff:
            cmd.itype = self.inames["dbrk"]
            opcode_size = 2
        elif opcode[0:12].uint == 0xa05 and opcode[17:18].uint == 0x0:
            cmd.itype = self.inames["di"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:7].uint == 0x34 and opcode[22:27].uint == 0x0:
            cmd.itype = self.inames["dmt"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xc and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["dv"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xd and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["dvf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xf and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["dvfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xc and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["dvi"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xe and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["dvim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xc and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["dvis"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xe and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["dvism"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xe and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["dvm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xc and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["dvs"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = SIGNEXT(opcode[17:22].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xe and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["dvsm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = SIGNEXT(opcode[17:22].uint,5)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa04 and opcode[17:18].uint == 0x0:
            cmd.itype = self.inames["ei"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:9].uint == 0x145 and opcode[19:27].uint == 0x0:
            cmd.itype = self.inames["fti"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x147 and opcode[19:27].uint == 0x0:
            cmd.itype = self.inames["ftim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:18].uint == 0x280c0:
            cmd.itype = self.inames["ht"]
            opcode_size = 2
        elif opcode[0:18].uint == 0x28040:
            cmd.itype = self.inames["ir"]
            opcode_size = 2
        elif opcode[0:9].uint == 0x144 and opcode[19:27].uint == 0x0:
            cmd.itype = self.inames["itf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x146 and opcode[19:27].uint == 0x0:
            cmd.itype = self.inames["itfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x54 and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["lds"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:7].uint == 0x56 and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["ldt"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint,27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:7].uint == 0x55 and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["ldw"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:7].uint == 0x10 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["md"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x11 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mdf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x13 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mdfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x10 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["mdi"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x12 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["mdim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x10 and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["mdis"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x12 and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["mdism"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x12 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mdm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x10 and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["mds"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x12 and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["mdsm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = SIGNEXT(opcode[17:22].uint,5)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:5].uint == 0x11:
            cmd.itype = self.inames["mh"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[5:10].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_imm
            cmd[1].value = opcode[10:27].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:5].uint == 0x12:
            cmd.itype = self.inames["ml"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[5:10].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_imm
            cmd[1].value = opcode[10:27].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:5].uint == 0x13:
            cmd.itype = self.inames["ms"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[5:10].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_imm
            cmd[1].value = SIGNEXT(opcode[10:27].uint,17)
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x8 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mu"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x9 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["muf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xb and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mufm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x8 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["mui"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xa and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["muim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x8 and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["muis"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xa and opcode[24:26].uint == 0x3:
            cmd.itype = self.inames["muism"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = SIGNEXT(opcode[17:24].uint,7)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xa and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["mum"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x8 and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["mus"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0xa and opcode[22:26].uint == 0x2:
            cmd.itype = self.inames["musm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = SIGNEXT(opcode[17:22].uint,5)
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14c and opcode[19:26].uint == 0x0:
            cmd.itype = self.inames["ng"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14d and opcode[19:26].uint == 0x0:
            cmd.itype = self.inames["ngf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14f and opcode[19:26].uint == 0x0:
            cmd.itype = self.inames["ngfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14e and opcode[19:26].uint == 0x0:
            cmd.itype = self.inames["ngm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14c and opcode[19:26].uint == 0x20:
            cmd.itype = self.inames["nt"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14e and opcode[19:26].uint == 0x20:
            cmd.itype = self.inames["ntm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[14:19].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x18 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["or"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x18 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["ori"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x1a and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["orm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:18].uint == 0x28000:
            cmd.itype = self.inames["re"]
            opcode_size = 2
        elif opcode[0:12].uint == 0xa0c and opcode[17:18].uint == 0x0:
            cmd.itype = self.inames["rf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:7].uint == 0x30 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["rl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x40 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["rli"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x42 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["rlim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x32 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["rlm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x52 and opcode[17:27].uint == 0x0:
            cmd.itype = self.inames["rmp"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14c and opcode[14:26].uint == 0x60:
            cmd.itype = self.inames["rnd"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:9].uint == 0x14e and opcode[14:26].uint == 0x60:
            cmd.itype = self.inames["rndm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[9:14].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x31 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["rr"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x41 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["rri"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x43 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["rrim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x33 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["rrm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2d and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sa"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x3d and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["sai"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x3f and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["saim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2f and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sam"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x4 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sb"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x24 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sbc"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x24 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["sbci"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x26 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["sbcim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x26 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sbcm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x5 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sbf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x7 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sbfm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x4 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["sbi"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x6 and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["sbim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x6 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sbm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa07 and opcode[22:27].uint == 0x0:
            cmd.itype = self.inames["ses"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[17:22].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa08 and opcode[22:27].uint == 0x0:
            cmd.itype = self.inames["sew"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[17:22].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa0b and opcode[17:18].uint == 0x0:
            cmd.itype = self.inames["sf"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            opcode_size = 2
        elif opcode[0:7].uint == 0x28 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sl"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x38 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["sli"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x3a and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["slim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2a and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["slm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x52 and opcode[17:18].uint == 0x1 and opcode[20:27].uint == 0x0:
            cmd.itype = self.inames["smp"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            # TODO
            opcode_size = 3
        elif opcode[0:7].uint == 0x29 and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["sr"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x39 and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["sri"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x3b and opcode[24:26].uint == 0x0:
            cmd.itype = self.inames["srim"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x2b and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["srm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x58 and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["sts"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:7].uint == 0x5a and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["stt"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:7].uint == 0x59 and opcode[51:54].uint == 0x0:
            cmd.itype = self.inames["stw"]
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12].uint
            cmd[0].value = opcode[17:22].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17].uint
            cmd[1].addr = SIGNEXT(opcode[24:51].uint, 27)
            cmd[1].dtyp = dt_dword
            opcode_size = 6
        elif opcode[0:18].uint == 0x28080:
            cmd.itype = self.inames["wt"]
            opcode_size = 2
        elif opcode[0:7].uint == 0x1c and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["xr"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x1c and opcode[24:26].uint == 0x1:
            cmd.itype = self.inames["xri"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_imm
            cmd[2].value = opcode[17:24].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:7].uint == 0x1e and opcode[22:26].uint == 0x0:
            cmd.itype = self.inames["xrm"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[7:12].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[12:17].uint
            cmd[1].dtyp = dt_dword
            cmd[2].type = o_reg
            cmd[2].reg = opcode[17:22].uint
            cmd[2].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa09 and opcode[22:27].uint == 0x0:
            cmd.itype = self.inames["zes"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[17:22].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        elif opcode[0:12].uint == 0xa0a and opcode[22:27].uint == 0x0:
            cmd.itype = self.inames["zew"]
            cmd[0].type = o_reg
            cmd[0].reg = opcode[12:17].uint
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_reg
            cmd[1].reg = opcode[17:22].uint
            cmd[1].dtyp = dt_dword
            opcode_size = 3
        else:
            raise DecodingError()
        if "Multi Reg" in self.instrs[cmd.itype]['cmt']:
            cmd[0].specval |= FL_MULTIREG
            cmd[1].specval |= FL_MULTIREG
        self.cmd.size = opcode_size
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
        if self.cmd.itype == self.inames['mh']:
            # print "lui at: %08X on reg %s value %Xh\n" % (self.cmd.ea, self.regNames[self.cmd[0].reg], self.cmd[1].value)
            self.remove_mh_array_object(self.cmd[0].reg)
            self.last_mh_array.append({"reg": self.cmd[0].reg, "value": self.cmd[1].value})
            return
        elif self.cmd.itype == self.inames['lds'] or self.cmd.itype == self.inames['ldt'] \
                or self.cmd.itype == self.inames['ldw'] or self.cmd.itype == self.inames['sts'] \
                or self.cmd.itype == self.inames['stt'] or self.cmd.itype == self.inames['stw']:
            last_record_mh = self.get_mh_array_object(self.cmd[1].reg)
            self.remove_mh_array_object(self.cmd[0].reg)
            if last_record_mh != None:
                target_offset = toInt((last_record_mh["value"] << 12) + self.cmd[1].addr)
                if (isLoaded(target_offset)):
                    ua_add_dref(0, target_offset, dr_R)
                self.add_auto_resolved_constant_comment(target_offset)
        elif self.cmd[1].reg != None:
            cmd = self.cmd
            ft = cmd.get_canon_feature()
            if ft & CF_CHG1:
                last_record_mh = self.get_mh_array_object(self.cmd[1].reg)
                self.remove_mh_array_object(self.cmd[0].reg)
                if last_record_mh != None:
                    # print "trying to match addi or jalr for lui, cur ea: %08X" % (self.cmd.ea)
                    if self.cmd.itype == self.inames['ml'] or self.cmd.itype == self.inames['ms']:
                        target_offset = toInt((last_record_mh["value"] << 10) + self.cmd[2].value)
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
        if self.cmd[0].reg != None and self.cmd[0].reg == 2 and self.cmd[1].reg != None and self.cmd[1].reg == 2 and \
                        self.cmd.itype in [self.inames['addi'], self.inames['addid'], self.inames['addiw']]:
            # print self.cmd[2].value
            spofs = toInt(self.cmd[2].value)
            # print spofs
            self.add_stkpnt(self.cmd.ea, spofs)

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
            if fl & FL_MULTIREG:
                out_symbol(":")
                out_register(self.regNames[op.reg+1])

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

    # 处理是否是call指令（其实没什么用- -
    # 返回<=0不是，返回2是，返回1不知道
    def notify_is_call_insn(self, ea):
        cmd = self.cmd
        if cmd.itype == self.inames['jal']:
            if cmd[0].reg == 0:
                return 0
            elif cmd[0].reg == 1:
                return 2
            else:
                return 1
            pass
        elif cmd.itype == self.inames['jalr']:
            if cmd[0].reg == 0:
                return 0
            elif cmd[1].reg == 1 and cmd[1].addr == 0:
                return 0
            elif cmd[0].reg == 1:
                return 2
            else:
                return 1

def PROCESSOR_ENTRY():
    return openrisc_processor_t()
