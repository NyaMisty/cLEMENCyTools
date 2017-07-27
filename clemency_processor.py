# coding=utf-8

#import pydevd
#pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True,suspend=False,overwrite_prev_trace=True,patch_multiprocessing=True)

from idaapi import *
from idc import *
import idautils
import copy
import ctypes

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

FL_ABSOLUTE = 1  # absolute: &addr
FL_SYMBOLIC = 2  # symbolic: addr

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
        "CS", "DS"
    ]

    instruc = instrs = [
        #{'name': 'lui', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'lui rd,imm'},
        # 在这里按照上面的格式添加指令~~
        {'name': 'AD', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add	AD rA, rB, rC'},
        {'name': 'ADC', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add With Carry	ADC rA, rB, rC'},
        {'name': 'ADCI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Immediate With Carry	ADCI rA, rB, IMM'},
        {'name': 'ADCIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Add Immediate Multi Reg With Carry	ADCIM rA, rB, IMM'},
        {'name': 'ADCM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Multi Reg With Carry	ADCM rA, rB, rC'},
        {'name': 'ADF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Floating Point	ADF rA, rB, rC'},
        {'name': 'ADFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Add Floating Point Multi Reg	ADFM rA, rB, rC'},
        {'name': 'ADI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Immediate	ADI rA, rB, IMM'},
        {'name': 'ADIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Immediate Multi Reg	ADIM rA, rB, IMM'},
        {'name': 'ADM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Add Multi Reg	ADM rA, rB, rC'},
        {'name': 'AN', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'And	AN rA, rB, rC'},
        {'name': 'ANI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'And Immediate	ANI rA, rB, IMM'},
        {'name': 'ANM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'And Multi Reg	ANM rA, rB, rC'},
        {'name': 'B', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Branch Conditional	Bcc Offset'},
        {'name': 'BF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Bit Flip	BF rA, rB'},
        {'name': 'BFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Bit Flip Multi Reg	BFM rA, rB'},
        {'name': 'BR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Branch Register Conditional	BRcc rA'},
        {'name': 'BRA', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Branch Absolute	BRA Location'},
        {'name': 'BRR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Branch Relative	BRR Offset'},
        {'name': 'C', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Call Conditional	Ccc Offset'},
        {'name': 'CAA', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Call Absolute	CAA Location'},
        {'name': 'CAR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Call Relative	CAR Offset'},
        {'name': 'CM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Compare	CM rA, rB'},
        {'name': 'CMF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Compare Floating Point	CMF rA, rB'},
        {'name': 'CMFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Compare Floating Point Multi Reg	CMFM rA, rB'},
        {'name': 'CMI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Compare Immediate	CMI rA, IMM'},
        {'name': 'CMIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Compare Immediate Multi Reg	CMIM rA, IMM'},
        {'name': 'CMM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Compare Multi Reg	CMM rA, rB'},
        {'name': 'CR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Call Register Conditional	CRcc rA'},
        {'name': 'DBRK', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Debug Break	DBRK'},
        {'name': 'DI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Disable Interrupts	DI rA'},
        {'name': 'DMT', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Direct Memory Transfer	DMT rA, rB, rC'},
        {'name': 'DV', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide	DV rA, rB, rC'},
        {'name': 'DVF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Floating Point	DVF rA, rB, rC'},
        {'name': 'DVFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Divide Floating Point Multi Reg	DVFM rA, rB, rC'},
        {'name': 'DVI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Immediate	DVI rA, rB, IMM'},
        {'name': 'DVIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Divide Immediate Multi Reg	DVIM rA, rB, IMM'},
        {'name': 'DVIS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Immediate Signed	DVIS rA, rB, IMM'},
        {'name': 'DVISM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Divide Immediate Signed Multi Reg	DVISM rA, rB, IMM'},
        {'name': 'DVM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Multi Reg	DVM rA, rB, rC'},
        {'name': 'DVS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Signed	DVS rA, rB, rC'},
        {'name': 'DVSM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Signed Multi Reg	DVSM rA, rB, rC'},
        {'name': 'EI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Enable Interrupts	EI rA'},
        {'name': 'FTI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer	FTI rA, rB'},
        {'name': 'FTIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer Multi Reg	FTIM rA, rB'},
        {'name': 'HT', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Halt	HT'},
        {'name': 'IR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Interrupt Return	IR'},
        {'name': 'ITF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float	ITF rA, rB'},
        {'name': 'ITFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float Multi Reg	ITFM rA, rB'},
        {'name': 'LDS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Load Single	LDSm rA, [rB + Offset, RegCount]'},
        {'name': 'LDT', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Load Tri	LDTm rA, [rB + Offset, RegCount]'},
        {'name': 'LDW', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Load Word	LDWm rA, [rB + Offset, RegCount]'},
        {'name': 'MD', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus	MD rA, rB, rC'},
        {'name': 'MDF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Floating Point	MDF rA, rB, rC'},
        {'name': 'MDFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Modulus Floating Point Multi Reg	MDFM rA, rB, rC'},
        {'name': 'MDI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Immediate	MDI rA, rB, IMM'},
        {'name': 'MDIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Modulus Immediate Multi Reg	MDIM rA, rB, IMM'},
        {'name': 'MDIS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Immediate Signed	MDIS rA, rB, IMM'},
        {'name': 'MDISM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Modulus Immediate Signed Multi Reg	MDISM rA, rB, IMM'},
        {'name': 'MDM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Multi Reg	MDM rA, rB, rC'},
        {'name': 'MDS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Signed	MDS rA, rB, rC'},
        {'name': 'MDSM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Signed Multi Reg	MDSM rA, rB, rC'},
        {'name': 'MH', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move High	MH rA, IMM'},
        {'name': 'ML', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low	ML rA, IMM'},
        {'name': 'MS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low Signed	MS rA, IMM'},
        {'name': 'MU', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply	MU rA, rB, rC'},
        {'name': 'MUF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply Floating Point	MUF rA, rB, rC'},
        {'name': 'MUFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Multiply Floating Point Multi Reg	MUFM rA, rB, rC'},
        {'name': 'MUI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply Immediate	MUI rA, rB, IMM'},
        {'name': 'MUIM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Multiply Immediate Multi Reg	MUIM rA, rB, IMM'},
        {'name': 'MUIS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Multiply Immediate Signed	MUIS rA, rB, IMM'},
        {'name': 'MUISM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Multiply Immediate Signed Multi Reg	MUISM rA, rB, IMM'},
        {'name': 'MUM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply Multi Reg	MUM rA, rB, rC'},
        {'name': 'MUS', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply Signed	MUS rA, rB, rC'},
        {'name': 'MUSM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Multiply Signed Multi Reg	MUSM rA, rB, rC'},
        {'name': 'NG', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate	NG rA, rB'},
        {'name': 'NGF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Floating Point	NGF rA, rB'},
        {'name': 'NGFM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
         'cmt': 'Negate Floating Point Multi Reg	NGFM rA, rB'},
        {'name': 'NGM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Multi Reg	NGM rA, rB'},
        {'name': 'NT', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not	NT rA, rB'},
        {'name': 'NTM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not Multi Reg	NTM rA, rB'},
        {'name': 'OR', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Or	OR rA, rB, rC'},
        {'name': 'ORI', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Or Immediate	ORI rA, rB, IMM'},
        {'name': 'ORM', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Or Multi Reg	ORM rA, rB, rC'},
        {'name': 'RE', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Return	RE'},
        {'name': 'RF', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Read Flags	RF rA'},
        {'name': 'RL', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Rotate Left	RL rA, rB, rC'},
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

    def _read_cmd_2byte(self):
        ea = self.cmd.ea + self.cmd.size
        dword = get_full_byte(ea)
        self.cmd.size += 1
        return dword

    def _ana(self):
        cmd = self.cmd
        # ua_next_dword() is also ok :)
        opcode = self._read_cmd_dword()
        # 如果解析出错的话就raise这个exception，一般是像下面这样用
        # if ...... decode inst1
        # if ...... decode inst2
        # ....... decode.....
        # else:
        #    raise DecodingError()
        return cmd.size

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
        if self.cmd.itype == self.inames['lui']:
            # print "lui at: %08X on reg %s value %Xh\n" % (self.cmd.ea, self.regNames[self.cmd[0].reg], self.cmd[1].value)
            self.remove_mh_array_object(self.cmd[0].reg)
            self.last_mh_array.append({"reg": self.cmd[0].reg, "value": self.cmd[1].value})
            return
        elif self.cmd.itype == self.inames['ld'] or self.cmd.itype == self.inames['lw'] \
                or self.cmd.itype == self.inames['lh'] or self.cmd.itype == self.inames['lb'] \
                or self.cmd.itype == self.inames['ldu'] or self.cmd.itype == self.inames['lwu'] \
                or self.cmd.itype == self.inames['lhu'] or self.cmd.itype == self.inames['lbu']:
            last_record_lui = self.get_mh_array_object(self.cmd[1].reg)
            self.remove_mh_array_object(self.cmd[0].reg)
            if last_record_lui != None:
                target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[1].addr)
                if (isLoaded(target_offset)):
                    ua_add_dref(0, target_offset, dr_R)
                self.add_auto_resolved_constant_comment(target_offset)
        elif self.cmd[1].reg != None:
            cmd = self.cmd
            ft = cmd.get_canon_feature()
            if ft & CF_CHG1:
                last_record_lui = self.get_mh_array_object(self.cmd[1].reg)
                self.remove_mh_array_object(self.cmd[0].reg)
                if last_record_lui != None:
                    # print "trying to match addi or jalr for lui, cur ea: %08X" % (self.cmd.ea)
                    if self.cmd.itype == self.inames['addi']:
                        target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[2].value)
                        if (isLoaded(target_offset)):
                            ua_add_dref(0, target_offset, dr_R)
                        self.add_auto_resolved_constant_comment(target_offset)
                    elif self.cmd.itype == self.inames['jalr']:
                        if self.cmd[0].reg == 1 and self.cmd[1].reg == 1:
                            return
                        target_offset = toInt((last_record_lui["value"] << 12) + self.cmd[2].value)
                        if (isLoaded(target_offset)):
                            ua_add_cref(0, target_offset, fl_JN)
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

        # 首先对特殊指令做处理
        if cmd.itype == self.inames['jal']:
            # 无条件跳转 类似于x86 jmp
            if cmd[0].reg == 0:
                flow = False
                ua_add_cref(0, cmd[1].addr, fl_JN)
            # 带link跳转 类似于x86 call
            if cmd[0].reg == 1:
                flow = True
                ua_add_cref(0, cmd[1].addr, fl_CN)
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
            # 其他情况
            elif cmd[0].reg != 0:
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
                flow = True
            pass
        elif cmd.itype == self.inames['jalr']:
            # 无条件跳转
            if cmd[0].reg == 0:
                flow = False
            # 中间文件的用于重定位占位的特殊情况
            elif cmd[0].reg == 1 and cmd[1].reg == 1 and cmd[1].addr == 0:
                flow = True
            # 跳转至link 相当于retn
            elif cmd[1].reg == 1 and cmd[1].addr == 0:
                flow = False
            # 子函数调用 相当于call
            elif cmd[0].reg == 1:
                flow = True
                ua_add_cref(0, cmd.ea + cmd.size, fl_F)
                try:
                    nn = netnode("$ simplified_addr", 0, False)
                    if nn == BADNODE:
                        raise Exception("Resolved addr not found")
                    target = nn.altval(self.cmd.ea)
                    ua_add_cref(0, target, fl_CN)
                except:
                    print "Error while making function from cmd.ea:0x%X" % (cmd.ea)
            else:
                flow = False
        else:
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
