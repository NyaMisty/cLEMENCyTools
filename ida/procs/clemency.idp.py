# coding=utf-8

from idaapi import *
from idc import *
from constants import *
import idautils
import copy
import ctypes

def ToSignedInteger(x, bw):
    return x - (1 << bw) if x & (1 << (bw - 1)) else x

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
FL_MULTIREG = 0x000002000  # This is a multi reg operand

PRFL_UF = 0x1

FL_ABSOLUTE = 1  # absolute: &addr
FL_SYMBOLIC = 2  # symbolic: addr

o_regset = o_idpspec1
o_memflags = o_idpspec2

PR_TINFO = 0x20000000  # not present in python??


class DecodingError(Exception):
    pass


class ClemencyProcessorHook(IDP_Hooks):
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

    def get_autocmt(self):
        return 2

class clemency_data_type(data_type_t):
    def __init__(self):
        data_type_t.__init__(self, name="cLEMENCy",
                             value_size = 2, menu_name = "cLEMENCy string",
                             asm_keyword = ".clemency")

    def calc_item_size(self, ea, maxsize):
        # Custom data types may be used in structure definitions. If this case
        # ea is a member id. Check for this situation and return 1
        if is_member_id(ea):
            return 1
        ea_end = ea
        while ea_end - ea < maxsize:
            if not isLoaded(ea_end):
                break
            if Byte(ea_end) == 0:
                break
            ea_end += 1
        return ea_end - ea + 1

class clemency_data_format(data_format_t):
    FORMAT_NAME = "cLEMENCy string"
    def __init__(self):
        data_format_t.__init__(self, name=clemency_data_format.FORMAT_NAME)

    def printf(self, value, current_ea, operand_num, dtid):
        # Take the length byte
        retsize = get_item_size(current_ea)
        if retsize <= 0:
            return 0
        retsize -= 1
        buf = GetManyBytes(current_ea,retsize * 2)
        temp_buf = '"' + buf.decode('utf-16-le') + '", 0'
        temp_buf = temp_buf.replace('\r', '", 0Dh, "').replace('\n','", 0Ah, "').replace('"", ','')
        return temp_buf.encode("utf-8")

class clemency_tribyte_format(data_format_t):
    FORMAT_NAME = "cLEMENCy tribyte"
    def __init__(self):
        data_format_t.__init__(self, name="cLEMENCy tribyte",
                               value_size = 3,
                               menu_name = "Correct Middle Endian",
                               hotkey = "Shift-M")

    def printf(self, value, current_ea, operand_num, dtid):
        # Take the length byte
        byte1 = get_full_byte(current_ea) & 0x1ff
        byte2 = get_full_byte(current_ea+1) & 0x1ff
        byte3 = get_full_byte(current_ea+2) & 0x1ff
        simplified = byte2 << 18 | byte1 << 9 | byte3
        if isEnabled(simplified):
            ua_add_dref(0,simplified,dr_R)
        return "MIDDLE_ENDIAN(%Xh)" % (simplified)

new_formats = [
    (clemency_data_type(), clemency_data_format()),
    (clemency_tribyte_format(),),
    #(0,clemency_tribyte_format())
]

class BitStream(object):
    def __init__(self, v, bw):
        self.v = v
        self.bw = bw
    def append(self, b):
        return BitStream((self.v << b.bw) | b.v, self.bw + b.bw)
    def __getitem__(self, key):
        if type(key) is slice:
            if key.start is None:
                return self.v >> (self.bw-key.stop)
            if key.stop is None:
                raise IndexError('Weird Slice')
            if key.start > key.stop: raise IndexError('Funny Slice')
            return (self.v >> (self.bw-key.stop)) & ((1 << (key.stop-key.start))-1)
        elif type(key) is int:
            if key >= self.bw or key < 0: raise IndexError('Freaking Weird Index?!')
            return (self.v >> (self.bw-1-key)) & 1

def MiddleEndianToBigEndian(bits):
    assert bits.bw == 27
    return BitStream((bits[9:18] << 18) | (bits[0:9] << 9) | bits[18:27], 27)

# is sp delta fixed by the user?
def is_fixed_spd(ea):
    return (get_aflags(ea) & AFL_FIXEDSPD) != 0

class ClemencyProcessor(processor_t):
    # id = 0x8001 + 0x5571C
    # <TODO>: It must be > 0x8000?
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
        "flag": ASH_HEXF0 | ASD_DECF0 | ASO_OCTF5 | ASB_BINF0 | AS_N2CHR | AS_ASCIIZ,
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
        "a_3byte": ".tri",
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
    reg_names = regNames = [("R%d" % i) for i in range(29)] + \
                           ["ST", "RA", "PC", "FL"] + ["CS", "DS"]

    instruc = instrs = IDA_INSTR_DEF

    instruc_end = len(instruc) + 1
    idphook = None

    codestart = ['\x7a\x01\x03\x00']
    retcodes = ['\x00\x00\x40\x01']

    def __init__(self):
        super(ClemencyProcessor, self).__init__()
        self._init_instructions()
        self._init_registers()
        self.last_ml_array = [{'reg': -1, 'value': 0}]
        self.last_mh_array = [{'reg': -1, 'value': 0}]
        self.last_r27 = None

    def _init_instructions(self):
        self.inames = {}
        for idx, ins in enumerate(self.instrs):
            self.inames[ins['name']] = idx
            setattr(self, 'itype_' + ins['name'], idx)
        self.icode_return = self.inames['re']

    def _init_registers(self):
        self.reg_ids = {}
        for i, reg in enumerate(self.reg_names):
            self.reg_ids[reg] = i
            setattr(self, 'ireg_' + reg, i)
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
        return BitStream(self._read_cmd_byte(), 9)

    def _read_cmd_word_bitstr(self):
        word = reduce(lambda a, b: a.append(b), [self._read_cmd_byte_bitstr() for _ in xrange(3)])
        return MiddleEndianToBigEndian(word)

    def _ana(self):
        cmd = self.cmd
        opcode = self._read_cmd_word_bitstr()
        opcode_6 = opcode.append(self._read_cmd_word_bitstr())
        opcode_4 = BitStream(opcode_6[:27], 27).append(BitStream(opcode_6[36:45], 9))

        okay = False
        for bl in ISA_DEF_GROUPED_BY_OPLEN.keys():
            cop = opcode[:bl]
            insdic = ISA_DEF_GROUPED_BY_OPLEN[bl]
            if cop in insdic:
                for rins in insdic[cop]:
                    saved_opcode = opcode
                    opcode = opcode_4 if rins.size_in_bytes == 4 else opcode_6
                    if (rins.subopcode is None or opcode[rins.subopcode_start:rins.subopcode_start+rins.subopcode_bits] == rins.subopcode):
                        okay = True
                        break
                    opcode = saved_opcode
            if okay: break
        else:
            raise DecodingError()

        cmd.itype = self.inames[rins.name]
        opcode_size = rins.size_in_bytes
        self.cmd.size = opcode_size
        if rins.update_flag is not None:
            if opcode[rins.update_flag] == 1:
                cmd.auxpref |= PRFL_UF

        # This is kinda dirty...
        def ParseLoadStore():
            cmd[0].type = o_regset
            cmd[0].reg = opcode[7:12]
            cmd[0].value = opcode[17:22]
            cmd[0].dtyp = dt_dword
            cmd[1].type = o_displ
            cmd[1].specval |= FL_INDIRECT
            cmd[1].reg = opcode[12:17]
            cmd[1].addr = ToSignedInteger(opcode[24:51], 27)
            cmd[1].dtyp = dt_3byte
            adjB = opcode[22:24]
            newname = rins.name + ['', 'i', 'd'][adjB]
            cmd.itype = self.inames[newname]

        OverrideLDS = OverrideLDT = OverrideLDW = ParseLoadStore
        OverrideSTS = OverrideSTT = OverrideSTW = ParseLoadStore
        override_func_name = 'Override' + rins.name.upper()
        if override_func_name in locals():
            locals()[override_func_name]()
        else:
            idx = 0
            for oper in rins.operands:
                val = opcode[oper.start:oper.start+oper.width]
                if oper.name.startswith('r') and oper.name[1] in 'ABC':
                    cmd[idx].type = o_reg
                    cmd[idx].reg = val
                    # <TODO>: Remove this hack.
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
                    # cmd[idx].type = o_cc
                    # cmd[idx].specval = val # Condition code
                    # cmd[idx].clr_shown()
                    if val not in CONDSUFFIX:
                        raise DecodingError()
                    newname = rins.name + CONDSUFFIX[val]
                    cmd.itype = self.inames[newname]
                    continue # this is a virtual operand
                elif oper.name == 'Memory_Flags':
                    cmd[idx].type = o_memflags
                    cmd[idx].specval = val
                else:
                    raise NotImplementedError('Instruction {0} needs custom handler for its operands {1} but not implemented!'.format(rins.name, oper.name))
                cmd[idx].dtyp = dt_3byte
                idx += 1

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


    # 这三个是下面simplify的辅助函数可以看看供为参考
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
        nn = netnode("$ simplified_addr", 0, True)
        nn.altset(self.cmd.ea, resolved_offset & EA_BITMASK)
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
    # 这里是简单的化简 供参考用
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
                        #if (isLoaded(target_offset)):
                        ua_add_dref(0, target_offset, dr_R)
                        self.add_auto_resolved_constant_comment(target_offset)
                        if self.cmd[0].reg == self.ireg_R27:
                            self.last_r27 = (target_offset, self.cmd.ea)


    # 这个函数不用动哒
    def add_stkpnt(self, pfn, v):
        if pfn:
            end = self.cmd.ea + self.cmd.size
            if not is_fixed_spd(end):
                add_auto_stkpnt2(pfn, end, v)


    # 这里处理会修改sp的指令，如果懒or时间不够的话就留空吧
    def trace_sp(self):
        """
        Trace the value of the SP and create an SP change point if the current
        instruction modifies the SP.
        """
        pfn = get_func(self.cmd.ea)
        if not pfn:
           return
        spofs = 0
        # adi, sbi
        if self.cmd.itype in (self.itype_adi, self.itype_sbi) and \
           self.cmd[0].reg == self.ireg_ST and \
           self.cmd[1].reg == self.ireg_ST:
            spofs = self.cmd[2].value
            if self.cmd.itype == self.itype_sbi:
                spofs = -spofs

        if self.cmd.itype in (self.itype_ad, self.itype_sb) and \
           self.cmd[0].reg == self.ireg_ST and \
           self.cmd[1].reg == self.ireg_ST:
            if self.cmd[2].reg != self.ireg_R27:
                print 'Unknown stack adjustment @', hex(self.cmd.ea)
            else:
                if self.last_r27 is not None and self.last_r27[1] == self.cmd.ea - 3:
                    spofs = self.last_r27[0]
                else:
                    last_record_ml = self.get_ml_array_object(cmd[2].reg)
                    if last_record_ml:
                        spofs = last_record_ml['value']
            if self.cmd.itype == self.itype_sbi:
                spofs = -spofs 

        # load/store decrease
        elif self.cmd.itype in (self.itype_ldsd, self.itype_stsd) and self.cmd[1].reg == self.ireg_ST:
            spofs = -1 * (self.cmd[0].value + 1)
        elif self.cmd.itype in (self.itype_ldwd, self.itype_stwd) and self.cmd[1].reg == self.ireg_ST:
            spofs = -2 * (self.cmd[0].value + 1)
        elif self.cmd.itype in (self.itype_ldtd, self.itype_sttd) and self.cmd[1].reg == self.ireg_ST:
            spofs = -3 * (self.cmd[0].value + 1)

        # load/store increase
        elif self.cmd.itype in (self.itype_ldsi, self.itype_stsi) and self.cmd[1].reg == self.ireg_ST:
            spofs = 1 * (self.cmd[0].value + 1)
        elif self.cmd.itype in (self.itype_ldwi, self.itype_stwi) and self.cmd[1].reg == self.ireg_ST:
            spofs = 2 * (self.cmd[0].value + 1)
        elif self.cmd.itype in (self.itype_ldti, self.itype_stti) and self.cmd[1].reg == self.ireg_ST:
            spofs = 3 * (self.cmd[0].value + 1)

        if spofs != 0:
            self.add_stkpnt(pfn, spofs)


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

        if not ft & CF_STOP:
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
                out_register(self.regNames[op.reg + 1])

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
                out_register(self.regNames[op.reg + op.value])
        elif optype == o_memflags:
            if op.specval > 3: out_keyword("???")
            else: out_keyword(['NA', 'R', 'RW', 'E'][op.specval])
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
        if cmd.auxpref & PRFL_UF:
            OutMnem(15, ".")
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


    def notify_init(self, idp_file):
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
            self.idphook = ClemencyProcessorHook()
            self.idphook.hook()
        if not register_data_types_and_formats(new_formats):
            print 'Failed to register custom types.'
        else:
            print 'Custom types registered.'
        # cvar.inf.mf = LITTLE_ENDIAN
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
        unregister_data_types_and_formats(new_formats)

    # <TODO>
    def notify_may_be_func(self, state):
        if self.cmd.Op1.type == o_reg and self.cmd.Op1.reg == self.reg_ids['ST'] and self.cmd.Op2.type == o_reg and self.cmd.Op2.reg == self.reg_ids['ST'] and \
           cmd.itype in (self.inames['adi'], self.inames['sbi']):
            return 90
        return 10



def PROCESSOR_ENTRY():
    return ClemencyProcessor()
