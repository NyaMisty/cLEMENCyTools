# coding=utf-8

import pydevd
pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True, suspend=False)

from idaapi import *
from idc import *
from idautils import *
import traceback

class NoCorrespondingRegError(Exception):
    pass

class UnsupportedCornerCase(Exception):
    pass

def SIGNEXT(x, b):
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

class openrisc_translator_arm:
    f = None
    isCurInData = False
    xlen = 4
    curIndent = "   "
    lastLiteralPool = 0
    auto_extend = False
    def __init__(self,name):
        self.f = open(name,"w")
    #辅助函数 可以自动处理indent 也可以在特殊情况指定indent
    def out(self, buf, indent=None):
        if not self.f is None:
            if indent is None:
                self.f.write(self.curIndent + buf + "\n")
            else:
                self.f.write(indent + buf + "\n")
    #生成label名称
    def getRealName(self,ea):
        name = Name(ea)
        if name != "":
            name += ""
        elif name == "" and isLoaded(ea):
            name = ("loc_%0" + str(self.xlen * 2) + "X") % (ea)
        else:
            name = ""
        return name
    #与processor协同 使用processor的分析结果
    def translateComment(self,ea):
        #ref = Comment(ea)
        target = BADADDR
        nn = netnode("$ simplified_addr", 0, False)
        if nn != BADNODE:
            target = nn.altval(ea)
        if target != BADADDR and target != 0:
            return target
        nn = netnode("$ simplified_const", 0, False)
        if nn != BADNODE:
            target = nn.altval(ea)
        if target == 0:
            return BADADDR
        if not isLoaded(target):
            return BADADDR
        return target
    #如果生成的汇编文件有header的话加在这里
    def printAsmHeader(self):
        pass

    # 如果生成的汇编文件有结尾的话加在这里
    def printAsmFooter(self):
        #self.out("  END")
        pass

    # 每一个区段自己的header
    def printSegHeader(self,ea,attr):
        segHeader = ".text"
        """segHeader = ".section   "
        segHeader += SegName(ea)
        segHeader += ""
        if attr & SEGPERM_EXEC:
            segHeader += ", '"
        else:
            segHeader += ", 'x"
        if isLoaded(ea):
            segHeader += "a"
        if attr & SEGPERM_READ and attr & SEGPERM_WRITE:
            segHeader += "w"
        elif attr & SEGPERM_READ and not attr & SEGPERM_WRITE:
            segHeader += ""
        else:
            print "Warning: seg at 0x%X named %s does not have a read permission, please check!" % (ea, SegName(ea))
        segHeader += ("'              @ Segment at %0"+ str(self.xlen * 2) +"X %s") % (ea, SegName(ea))"""
        self.out(segHeader)
    #获取data中的offset
    """def calcOffsetTargetAndBase(self, ea, value):
        refi = opinfo_t()
        get_opinfo(ea, 0, GetFlags(ea), refi)

        reftarget = calc_reference_target(ea, refi.ri, value)
        return reftarget,refi.ri.base"""

    def calcOffsetTargetAndBase(self, ea, value):
        return value, 0

    def getFirstXref(self, ea):
        for i in XrefsTo(ea):
            return i
    ########################################################
    ########################################################
    #似乎并不需要重新定位pc，因为不考虑relocation的情况下，pc是个常量
    #或许应该在translator里面处理这个的
    #但是这可能会导致hexrays无法正常工作QAQ
    #
    #决定重新定位pc，否则很可能会影响arm反汇编
    #否决上述决定
    #经试验后发现IDA可以处理这种情况，
    #重新决定为不重定位pc
    ########################################################
    def makeOffsetExpression(self,ea,target,base):
        expression = ""
        expression += self.getRealName(target)
        if base != 0 and base == self.getFirstXref(ea):
            expression += " - "
            """if hasName(base):
                expression += self.getRealName(base)
            else:
                expression += ("loc_%0"+ str(self.xlen * 2) +"X") % (base)"""
            expression += "0x%X" % (base)
        return expression
    #上面的三个函数是想要处理重定位的，不过发现hexrays可以自动处理这些情况
    #所以如果还是需要处理的话就改上面的几个

    #翻译数据
    def doDataTranslation(self,ea):
        oriea = ea
        curline = ""
        curflag = GetFlags(ea)
        if not self.isCurInData:
            #self.out("DATA")
            self.isCurInData = True
        self.out(self.getRealName(ea) + ":","")
        self.out(self.getRealName(ea) + ":","")
        if not isLoaded(ea):
            curline += ".hword 0"
            ea += 1
        elif isData(curflag):
            if isOff0(curflag):
                if isByte(curflag):
                    curline += ".hword "
                    target, base = self.calcOffsetTargetAndBase(ea, Byte(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    ea += 1
                    print "Warning: Offset typed byte appeared"
                    """
                elif isWord(curflag):
                    curline += ".word "
                    target, base = self.calcOffsetTargetAndBase(ea, Word(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    #curline += self.getRealName(target)
                    ea += 2
                """
                elif is3byte(curflag):
                    byte1 = get_full_byte(ea) & 0x1ff
                    byte2 = get_full_byte(ea + 1) & 0x1ff
                    byte3 = get_full_byte(ea + 2) & 0x1ff
                    simplified = byte2 << 18 | byte1 << 9 | byte3
                    curline += ".dword "

                    target, base = self.calcOffsetTargetAndBase(ea, simplified(ea))
                    curline += self.makeOffsetExpression(ea, target, base)
                    #curline += self.getRealName(target)
                    ea += 3
                else:
                    print ("Warning: not supported data type at %0"+str(self.xlen * 2)+"X") % (ea)
                    curline += ".hword %d\n" % (Byte(ea))
                    ea += 1
            else:
                if isByte(curflag):
                    curline += ".hword %d\n" % (Byte(ea))
                    ea += 1
                    """
                elif isWord(curflag):
                    curline += ".word %d\n" % (Word(ea))
                    ea += 2
                """
                elif is3byte(curflag):
                    byte1 = get_full_byte(ea) & 0x1ff
                    byte2 = get_full_byte(ea + 1) & 0x1ff
                    byte3 = get_full_byte(ea + 2) & 0x1ff
                    simplified = byte2 << 18 | byte1 << 9 | byte3
                    curline += ".dword %d\n" % (simplified)
                    ea += 3
                else:
                    curline += ".hword %d\n" % (Byte(ea))
                    ea += 1
        else:
            curline += ".hword %d\n" % (Byte(ea))
            ea += 1
        self.out(curline)
        return ea - oriea
    #避免助记符中带有特殊字符
    def cleanMnem(self, mnem):
        mnem.replace(".","_")
        mnem.replace(" ","_")
        return mnem

    #ARM中规定必须要4k之内有一个literal pool
    def custom_action1(self, ea):
        self.out("B %s" % (self.getRealName(ea)))
        self.out(".ltorg")
        self.lastLiteralPool = 0

    # 翻译指令
    def doCodeSegTranslation(self,ea):
        self.isCurInData = False
        oriea = ea
        while ea < SegEnd(oriea):
            curline = ""
            if isCode(GetFlags(ea)):
                if self.isCurInData:
                    self.isCurInData = False
                    self.out(".balign 4")
                length = decode_insn(ea)
                if length <= 0:
                    length = self.doDataTranslation(ea)
                    self.lastLiteralPool += length
                    ea += length
                    continue

                if self.lastLiteralPool >= 0x900:
                    self.custom_action1(ea)

                mnem = GetMnem(ea)
                curline += self.getRealName(ea)
                curline += ":"
                #curline += "    NOP"
                self.out(curline, "")
                ########here!! dispatch the translator!!!
                mnem = self.cleanMnem(mnem)
                if mnem[-1:] == "_":
                    mnem = mnem[:-1]
                try:
                    self.auto_extend = False
                    getattr(self, 'translator_%s' % mnem)(ea,cmd)
                except AttributeError as e:
                    print ("%0"+str(self.xlen * 2)+"X: Warning: translator of %s instruction is not implemented! ") % (ea,mnem)
                    traceback.print_exc()
                #如果出现异常 那么就用4个nop填充一下，以便修复和鉴别
                except Exception as e:
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    self.out("NOP")
                    print ("%0"+str(self.xlen * 2)+"X: %s") % (ea,repr(e))
                self.lastLiteralPool += 12
                ea += length
                continue
            else:
                length = self.doDataTranslation(ea)
                self.lastLiteralPool += length
                ea += length

    #处理数据区段
    def doOtherSegTranslation(self,ea):
        self.isCurInData = True
        oriea = ea
        while ea < SegEnd(oriea):
            ea += self.doDataTranslation(ea)
    #处理导出区段
    def doExternSegTranslation(self,ea):
        oriea = ea
        while ea < SegEnd(oriea):
            curline = "     EXTERN "
            curline += self.getRealName(ea)
            curline += "[WEAK]"
            self.out(curline)
            ea += self.xlen
    #增加用于存储多出来的寄存器的区段
    """def makeGlobalSegment(self):
        segHeader = ".section "
        segHeader += ".global"
        segHeader += ", "
        segHeader += "DATA, "
        segHeader += "NOINIT, "
        segHeader += "READWRITE"
        segHeader += ("              @ Global segment")
        self.out(segHeader)
        for idx,name in enumerate(self.reg_names_target):
            curline = ""
            if name == self.temp_register:
                curline += "ori_register_%s    " % (self.reg_names_origin[idx])
                curline += ".space %d" % (self.xlen)
            elif name == self.temp_register_gp:
                self.out(".space %d" % (1000))
                curline += "global_pointer_%s    " % (self.reg_names_origin[idx])
                curline += ".space %d" % (1000)
            self.out(curline,"")"""

    #下面是寄存器的映射关系
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
        "RA", "PC",
        "CS", "DS"
    ]

    reg_names_target = [
        "X0", "X1", "X2", "X3", "X4",
        "X5", "X6", "X7", "X8", "X9",
        "X10", "X11", "X12", "X13", "X14",
        "X15", "X16", "X17", "X18", "X19",
        "X20", "X21", "X22", "X23", "X24",
        "X25", "X26", "X27", "X29", "SP",
        "X30", "",
        "CS", "DS"
    ]
    temp_register = "W28"
    temp_register_long = "X28"
    """temp_register_addr存储多出来的寄存器的地址
    #temp_register_gp用于处理gp寄存器的使用
    #temp_register 存储多出来寄存器的值
    #temp_register_offset 用于处理内存访问时offset大于可支持范围的情况
    temp_register = "R8"
    temp_register_addr = "R11"
    temp_register_gp = "R10"
    temp_register_offset = "R9
    def premap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("ldur %s, [%s]" % (self.temp_register, self.temp_register_addr))
        elif self.reg_names_target[ori_reg] == self.temp_register_gp:
            self.out("LDR %s, =global_pointer_%s" % (self.temp_register_gp, self.reg_names_origin[ori_reg]))
        return self.reg_names_target[ori_reg]

    def postmap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        elif self.reg_names_target[ori_reg] == self.temp_register:
            self.out("LDR %s, =ori_register_%s" % (self.temp_register_addr, self.reg_names_origin[ori_reg]))
            self.out("stur %s, [%s]" % (self.temp_register, self.temp_register_addr))
"""
    def premap_registers(self,ori_reg,isLong=False):
        if self.auto_extend:
            isLong = True
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        if self.reg_names_target[ori_reg] == "SP":
            self.auto_extend = True
            return "SP"
        if self.reg_names_target[ori_reg] == "X29":
            self.auto_extend = True
            return "X29"
        if self.reg_names_target[ori_reg][0] == "X" and not isLong:
            return "W" + self.reg_names_target[ori_reg][1:]

        return self.reg_names_target[ori_reg]
    def premap_float_registers(self,ori_reg,isLong=False):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
        if self.reg_names_target[ori_reg][0] == "X":
            if isLong:
                return "D" + self.reg_names_target[ori_reg][1:]
            else:
                return "S" + self.reg_names_target[ori_reg][1:]
        else:
            raise NoCorrespondingRegError()

    def postmap_registers(self, ori_reg):
        if self.reg_names_target[ori_reg] == "":
            raise NoCorrespondingRegError()
    #下面就是translator了，注意特殊情况的处理哦
    #可能大量算数运算是无需进行更改的
    def translator_ad(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("add %s, %s, %s" % (rA , rB, rC))
        pass

    def translator_adc(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("add %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_adci(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("add %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_adcim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("add %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_adcm(self, ea, cmd):
       rA = self.premap_registers(cmd[0].reg,True)
       rB = self.premap_registers(cmd[1].reg,True)
       rC = self.premap_registers(cmd[2].reg,True)
       self.out("add %s, %s, %s"% (rA, rB, rC))
       pass

    def translator_adf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        rC = self.premap_float_registers(cmd[2].reg)
        self.out("fadd %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_adfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        rC = self.premap_float_registers(cmd[2].reg,True)
        self.out("fadd %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_adi(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("add %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_adim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("add %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_adm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("add %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_an(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("and %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_ani(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("and %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_anm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("and %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_bn(self, ea, cmd):
        self.out("bne %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_be(self, ea, cmd):
        self.out("beq %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bl(self, ea, cmd):
        self.out("blo %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_ble(self, ea, cmd):
        self.out("bls %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bg(self, ea, cmd):
        self.out("bhi %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bge(self, ea, cmd):
        self.out("bhs %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bno(self, ea, cmd):
        self.out("bvc %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bo(self, ea, cmd):
        self.out("bvs %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bns(self, ea, cmd):
        self.out("bpl %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bs(self, ea, cmd):
        self.out("bmi %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bsl(self, ea, cmd):
        self.out("blt %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bsle(self, ea, cmd):
        self.out("ble %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bsg(self, ea, cmd):
        self.out("bgt %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bsge(self, ea, cmd):
        self.out("bge %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_b(self, ea, cmd):
        self.out("b %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_bf(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("neg %s, %s" % (rA,rB))
        pass

    def translator_bfm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("neg %s, %s" % (rA, rB))
        pass

    def translator_brn(self, ea, cmd):
        self.out("bne %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_bre(self, ea, cmd):
        self.out("beq %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brl(self, ea, cmd):
        self.out("blo %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brle(self, ea, cmd):
        self.out("bls %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brg(self, ea, cmd):
        self.out("bhi %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brge(self, ea, cmd):
        self.out("bhs %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brno(self, ea, cmd):
        self.out("bvc %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_bro(self, ea, cmd):
        self.out("bvs %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brns(self, ea, cmd):
        self.out("bpl %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brs(self, ea, cmd):
        self.out("bmi %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brsl(self, ea, cmd):
        self.out("blt %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brsle(self, ea, cmd):
        self.out("ble %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brsg(self, ea, cmd):
        self.out("bgt %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_brsge(self, ea, cmd):
        self.out("bge %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_br(self, ea, cmd):
        self.out("br %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_bra(self, ea, cmd):
        self.out("b %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_brr(self, ea, cmd):
        self.out("b %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cn(self, ea, cmd):
        self.out("blne %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_ce(self, ea, cmd):
        self.out("bleq %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cl(self, ea, cmd):
        self.out("bllo %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cle(self, ea, cmd):
        self.out("blls %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cg(self, ea, cmd):
        self.out("blhi %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cge(self, ea, cmd):
        self.out("blhs %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cno(self, ea, cmd):
        self.out("blvc %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_co(self, ea, cmd):
        self.out("blvs %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cns(self, ea, cmd):
        self.out("blpl %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cs(self, ea, cmd):
        self.out("blmi %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_csl(self, ea, cmd):
        self.out("bllt %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_csle(self, ea, cmd):
        self.out("blle %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_csg(self, ea, cmd):
        self.out("blgt %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_csge(self, ea, cmd):
        self.out("blge %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_c(self, ea, cmd):
        self.out("bl %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_caa(self, ea, cmd):
        self.out("bl %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_car(self, ea, cmd):
        self.out("bl %s" % (self.getRealName(cmd[0].addr)))
        pass

    def translator_cm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("cmp %s, %s" % (rA, rB))
        pass

    def translator_cmf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        self.out("cmp %s, %s" % (rA, rB))
        pass

    def translator_cmfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        self.out("cmp %s, %s" % (rA, rB))
        pass

    def translator_cmi(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        self.out("cmp %s, #%d" % (rA, cmd[1].value))
        pass

    def translator_cmim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        self.out("cmp %s, #%d" % (rA, cmd[1].value))
        pass

    def translator_cmm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("cmp %s, %s" % (rA, rB))
        pass

    def translator_crn(self, ea, cmd):
        self.out("blne %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_cre(self, ea, cmd):
        self.out("bleq %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crl(self, ea, cmd):
        self.out("bllo %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crle(self, ea, cmd):
        self.out("blls %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crg(self, ea, cmd):
        self.out("blhi %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crge(self, ea, cmd):
        self.out("blhs %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crno(self, ea, cmd):
        self.out("blvc %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_cro(self, ea, cmd):
        self.out("blvs %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crns(self, ea, cmd):
        self.out("blpl %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crs(self, ea, cmd):
        self.out("blmi %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crsl(self, ea, cmd):
        self.out("bllt %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crsle(self, ea, cmd):
        self.out("blle %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crsg(self, ea, cmd):
        self.out("blgt %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_crsge(self, ea, cmd):
        self.out("blge %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_cr(self, ea, cmd):
        self.out("blr %s" % (self.premap_registers(cmd[0].reg,True)))
        pass

    def translator_dbrk(self, ea, cmd):
        self.out("nop")
        self.out("nop")
        self.out("nop")
        pass

    def translator_dv(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out(("udiv %s, %s, %s") % (rA,rB,rC))
        pass

    def translator_dvf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        rC = self.premap_float_registers(cmd[2].reg)
        self.out(("fdiv %s, %s, %s") % (rA, rB, rC))
        pass

    def translator_dvfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        rC = self.premap_float_registers(cmd[2].reg,True)
        self.out(("fdiv %s, %s, %s") % (rA, rB, rC))
        pass

    def translator_dvi(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s, =%d" % (self.temp_register, cmd[2].value))
        self.out(("udiv %s, %s, %s") % (rA, rB, self.temp_register))
        pass

    def translator_dvim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("ldr %s, =%d" % (self.temp_register_long, cmd[2].value))
        self.out(("udiv %s, %s, %s") % (rA, rB, self.temp_register_long))
        pass

    def translator_dvis(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s, =%d" % (self.temp_register,cmd[2].value))
        self.out(("sdiv %s, %s, %s") % (rA, rB, self.temp_register))
        pass

    def translator_dvism(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("ldr %s, =%d" % (self.temp_register_long, cmd[2].value))
        self.out(("sdiv %s, %s, #%d") % (rA, rB, self.temp_register_long))
        pass

    def translator_dvm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out(("udiv %s, %s, %s") % (rA, rB, rC))
        pass

    def translator_dvs(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out(("sdiv %s, %s, %s") % (rA, rB, rC))
        pass

    def translator_dvsm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        self.out(("sdiv %s, %s, %s") % (rA, rB, rC))
        pass

    def translator_fti(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        self.out(("fcvtzu %s, %s") % (rA, rB))
        pass

    def translator_ftim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_float_registers(cmd[1].reg, True)
        self.out(("fcvtzs %s, %s") % (rA, rB))
        pass

    def translator_ht(self, ea, cmd):
        self.out("b %s" % (self.getRealName(ea)))
        pass

    def translator_itf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        self.out(("scvtf %s, %s") % (rA, rB))
        pass

    def translator_itfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out(("scvtf %s, %s") % (rA, rB))
        pass

    def translator_lds(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            #Registers[StartReg] = Memory[MemLocation]
            self.out(("ldurh %s, [%s, #%d]") % (self.premap_registers(StartReg),self.premap_registers(cmd[1].reg,True), MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_ldt(self, ea, cmd):
        if cmd[0].reg == 28 and cmd[1].reg == 28 and cmd[0].value == 2 and cmd[1].value == 0:
            self.out("mov sp, x29")
            self.out("ldp x29,x30, [x29, #0]")
            pass
        else:
            StartReg = cmd[0].reg
            RegCount = cmd[0].value + 1
            CurCount = RegCount
            MemLocation = 0
            while CurCount != 0:
                # Registers[StartReg] = Memory[MemLocation]
                self.out(("ldur %s, [%s, #%d]") % (self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
                MemLocation += 6
                StartReg = (StartReg + 1) % 32
                CurCount = CurCount - 1
            # TODO
        pass

    def translator_ldw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldur %s, [%s, #%d]") % (
            self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_ldis(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        Temp = self.premap_registers(cmd[1].reg, True)
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out("ldurh %s, [%s, #%d]" % (
            self.premap_registers(StartReg), Temp, MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        #self.out("add %s, %s, #%d" % (Temp, Temp, MemLocation))
        pass

    def translator_ldsi(self, ea, cmd):
        translator_ldis(self, ea, cmd)

    def translator_ldit(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldur %s, [%s, #%d]") % (
            self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 6
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        #self.out("add %s, %s, #%d" % (Temp, Temp, MemLocation))
        # TODO
        pass

    def translator_ldti(self, ea, cmd):
        translator_ldit(self, ea, cmd)

    def translator_ldiw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldur %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_ldwi(self, ea, cmd):
        translator_ldiw(self, ea, cmd)

    def translator_ldds(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0 - CurCount
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldurh %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_ldsd(self, ea, cmd):
        translator_ldds(self, ea, cmd)

    def translator_lddt(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0 - CurCount*3
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldur %s, [%s, #%d]") % (
                self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 6
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        # TODO
        pass

    def translator_ldtd(self, ea, cmd):
        translator_lddt(self, ea, cmd)

    def translator_lddw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0 - CurCount * 2
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("ldur %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_ldwd(self, ea, cmd):
        translator_lddw(self, ea, cmd)

    def translator_md(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        self.out("udiv %s, %s, %s" % (rA, rB, rC))
        rAE = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("umsubl %s, %s, %s, %s" % (rAE, rA, rC, rB))
        pass

    def translator_mdf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        rC = self.premap_float_registers(cmd[2].reg)
        self.out("fdiv %s, %s, %s" % (rA, rB, rC))
        self.out("fnmadd %s, %s, %s, %s" % (rA, rA, rC, rB))
        pass

    def translator_mdfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        rC = self.premap_float_registers(cmd[2].reg,True)
        self.out("fdiv %s, %s, %s" % (rA, rB, rC))
        self.out("fnmadd %s, %s, %s, %s" % (rA, rA, rC, rB))
        pass

    def translator_mdi(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        rC = self.temp_register
        self.out("ldr %s,=%d" % (rC,cmd[2].value))
        self.out("udiv %s, %s, %s" % (rA, rB, rC))
        rAE = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("umsubl %s, %s, %s, %s" % (rAE, rA, rC, rB))
        pass

    def translator_mdim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.temp_register
        self.out("ldr %s,=%d" % (rC, cmd[2].value))
        self.out("udiv %s, %s, %s" % (rA, rB, rC))
        rAne = self.premap_registers(cmd[0].reg)
        self.out("umsubl %s, %s, %s, %s" % (rA, rAne, rC, rB))
        pass

    def translator_mdis(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        rC = self.temp_register
        self.out("ldr %s,=%d" % (rC, cmd[2].value))
        self.out("sdiv %s, %s, %s" % (rA, rB, rC))
        rAE = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("smsubl %s, %s, %s, %s" % (rAE, rA, rC, rB))
        pass

    def translator_mdism(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.temp_register
        self.out("ldr %s,=%d" % (rC, cmd[2].value))
        self.out("sdiv %s, %s, %s" % (rA, rB, rC))
        rAne = self.premap_registers(cmd[0].reg, True)
        self.out("smsubl %s, %s, %s, %s" % (rA, rAne, rC, rB))
        pass

    def translator_mdm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("udiv %s, %s, %s" % (rA, rB, rC))
        rAne = self.premap_registers(cmd[0].reg)
        rCne = self.premap_registers(cmd[2].reg)
        self.out("smsubl %s, %s, %s, %s" % (rA, rAne, rCne, rB))
        pass

    def translator_mds(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        self.out("sdiv %s, %s, %s" % (rA, rB, rC))
        rAE = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("smsubl %s, %s, %s, %s" % (rAE, rA, rC, rB))
        pass

    def translator_mdsm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("sdiv %s, %s, %s" % (rA, rB, rC))
        rAne = self.premap_registers(cmd[0].reg, True)
        rC = self.premap_registers(cmd[2].reg)
        self.out("smsubl %s, %s, %s, %s" % (rA, rAne, rC, rB))
        pass

    def translator_mh(self, ea, cmd):
        simplified = self.translateComment(ea)
        rA = self.premap_registers(cmd[0].reg)
        if simplified == BADADDR:
            self.out("ldr %s, =%d" % (self.temp_register, 0x3ff))
            self.out("and %s, %s, %s" % (rA, rA, self.temp_register))
            self.out("ldr %s, =%d" % (self.temp_register, cmd[1].value << 10))
            self.out("orr %s, %s, %s" % (rA, rA, self.temp_register))
        else:
            self.out("ldr %s, =%s" % (rA, self.getRealName(simplified)))
        pass

    def translator_ml(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        self.out("ldr %s, =%d" % (rA, cmd[1].value))
        pass

    def translator_ms(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        self.out("ldr %s, =%d" % (rA, cmd[1].value))
        pass

    def translator_mu(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("mul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_muf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        rC = self.premap_float_registers(cmd[2].reg)
        self.out("fmul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_mufm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        rC = self.premap_float_registers(cmd[2].reg,True)
        self.out("fmul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_mui(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s, =%d" % (rA, cmd[2].value))
        self.out("mul %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_muim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("ldr %s, =%d" % (rA, cmd[2].value))
        self.out("mul %s, %s, %s" % (rA, rB, self.temp_register_long))
        pass

    def translator_muis(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s, =%d" % (rA, cmd[2].value))
        self.out("mul %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_muism(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("ldr %s, =%d" % (rA, cmd[2].value))
        self.out("mul %s, %s, %s" % (rA, rB, self.temp_register_long))
        pass

    def translator_mum(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("mul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_mus(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("mul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_musm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        self.out("mul %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_ng(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("neg %s, %s" % (rA, rB))
        pass

    def translator_ngf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        self.out("fneg %s, %s" % (rA, rB))
        pass

    def translator_ngfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        self.out("fneg %s, %s" % (rA, rB))
        pass

    def translator_ngm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("neg %s, %s" % (rA, rB))
        pass

    def translator_nt(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("mvn %s, %s" % (rA, rB))
        pass

    def translator_ntm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("mvn %s, %s" % (rA, rB))
        pass

    def translator_or(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        if cmd[1].reg == cmd[2].reg:
            self.out("mov %s, %s" % (rA, rB))
        else:
            self.out("orr %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_ori(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s, =%d" % (rA, cmd[2].value))
        self.out("orr %s, %s, %s" % (rA, rB, cmd[2].value))
        pass

    def translator_orm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        if cmd[1].reg == cmd[2].reg:
            self.out("orr %s, %s" % (rA, rB))
        else:
            self.out("orr %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_re(self, ea, cmd):
        self.out("ret")
        pass

    def translator_rl(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("mov %s, 32" % (self.temp_register))
        self.out("sub %s, %s, %s" % (self.temp_register, self.temp_register, rC))
        self.out("ror %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_rli(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("mov %s, 32" % (self.temp_register))
        self.out("sub %s, %s, #%d" % (self.temp_register, self.temp_register, cmd[2].value))
        self.out("ror %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_rlim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("mov %s, 32" % (self.temp_register_long))
        self.out("sub %s, %s, #%d" % (self.temp_register_long, self.temp_register_long, cmd[2].value))
        self.out("ror %s, %s, %s" % (rA, rB, self.temp_register_long))
        pass

    def translator_rlm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("mov %s, 32" % (self.temp_register_long))
        self.out("sub %s, %s, %s" % (self.temp_register_long, self.temp_register_long, rC))
        self.out("ror %s, %s, %s" % (rA, rB, self.temp_register_long))
        pass

    def translator_rnd(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        self.out("ldr %s, =rand_num" % (rA))
        self.out("ldur %s, [%s]" % (rA, rA))
        pass

    def translator_rndm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        self.out("ldr %s, =rand_num" % (rA))
        self.out("ldur %s, [%s]" % (rA, rA))
        pass

    def translator_rr(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("ror %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_rri(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ror %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_rrim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("ror %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_rrm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("ror %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sa(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("sar %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sai(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ror %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_saim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("ror %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_sam(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        self.out("sar %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sb(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("sub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sbc(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("sub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sbci(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s,=%d" % (self.temp_register,cmd[2].value))
        self.out("sub %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_sbcim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        self.out("ldr %s,=%d" % (self.temp_register, cmd[2].value))
        self.out("sub %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_sbcm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("sub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sbf(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg)
        rB = self.premap_float_registers(cmd[1].reg)
        rC = self.premap_float_registers(cmd[2].reg)
        self.out("fsub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sbfm(self, ea, cmd):
        rA = self.premap_float_registers(cmd[0].reg,True)
        rB = self.premap_float_registers(cmd[1].reg,True)
        rC = self.premap_float_registers(cmd[2].reg,True)
        self.out("fsub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sbi(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("ldr %s,=%d" % (self.temp_register, cmd[2].value))
        self.out("sub %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_sbim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("ldr %s,=%d" % (self.temp_register, cmd[2].value))
        self.out("sub %s, %s, %s" % (rA, rB, self.temp_register))
        pass

    def translator_sbm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        self.out("sub %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_ses(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("sxth %s, %s" % (rA, rB))
        pass

    def translator_sew(self, ea, cmd):
        self.out("nop")
        pass

    def translator_sl(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("lsl %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sli(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("lsl %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_slim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("lsl %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_slm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("lsl %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sr(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("lsr %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sri(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("lsl %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_srim(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        self.out("lsl %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_srm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg,True)
        rB = self.premap_registers(cmd[1].reg,True)
        rC = self.premap_registers(cmd[2].reg,True)
        self.out("lsr %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_sts(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            #Registers[StartReg] = Memory[MemLocation]
            self.out(("sturh %s, [%s, #%d]") % (self.premap_registers(StartReg),self.premap_registers(cmd[1].reg,True), MemLocation))
            MemLocation += 6
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_stt(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("stur %s, [%s, #%d]") % (self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        # TODO
        pass

    def translator_stw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("stur %s, [%s, #%d]") % (
            self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_stis(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        Temp = self.premap_registers(cmd[1].reg, True)
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out("sturh %s, [%s, #%d]" % (
            self.premap_registers(StartReg), Temp, MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        self.out("add %s, %s, #%d" % (Temp, Temp, MemLocation))
        pass

    def translator_stsi(self, ea, cmd):
        translator_stis(self, ea, cmd)

    def translator_stit(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("stur %s, [%s, #%d]") % (
            self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 6
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_stti(self, ea, cmd):
        translator_stit(self, ea, cmd)

    def translator_stiw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("stur %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        pass

    def translator_stwi(self, ea, cmd):
        translator_stiw(self, ea, cmd)

    def translator_stds(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0 - CurCount
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("sturh %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 2
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        self.out(("sub %s, %s, #%d") % (
        self.premap_registers(cmd[1].reg, True), self.premap_registers(cmd[1].reg, True), RegCount))
        pass

    def translator_stsd(self, ea, cmd):
        translator_stds(self, ea, cmd)

    def translator_stdt(self, ea, cmd):
        if cmd[0].reg == 28 and cmd[1].reg == 29 and cmd[0].value == 2 and cmd[1].value == 0:
            self.out("stp x29, x30, [SP,#0]")
        else:
            StartReg = cmd[0].reg
            RegCount = cmd[0].value + 1
            CurCount = RegCount
            MemLocation = 0 - CurCount*3
            while CurCount != 0:
                # Registers[StartReg] = Memory[MemLocation]
                self.out(("stur %s, [%s, #%d]") % (
                    self.premap_registers(StartReg,True), self.premap_registers(cmd[1].reg, True), MemLocation))
                MemLocation += 6
                StartReg = (StartReg + 1) % 32
                CurCount = CurCount - 1
            self.out(("sub %s, %s, #%d") % (self.premap_registers(cmd[1].reg, True), self.premap_registers(cmd[1].reg, True),RegCount*3))
        pass

    def translator_sttd(self, ea, cmd):
        translator_stdt(self, ea, cmd)

    def translator_stdw(self, ea, cmd):
        StartReg = cmd[0].reg
        RegCount = cmd[0].value + 1
        CurCount = RegCount
        MemLocation = 0 - CurCount * 2
        while CurCount != 0:
            # Registers[StartReg] = Memory[MemLocation]
            self.out(("stur %s, [%s, #%d]") % (
                self.premap_registers(StartReg), self.premap_registers(cmd[1].reg, True), MemLocation))
            MemLocation += 4
            StartReg = (StartReg + 1) % 32
            CurCount = CurCount - 1
        self.out(("sub %s, %s, #%d") % (
        self.premap_registers(cmd[1].reg, True), self.premap_registers(cmd[1].reg, True), RegCount * 2))
        pass

    def translator_stwd(self, ea, cmd):
        translator_stdw(self, ea, cmd)

    def translator_xr(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        rC = self.premap_registers(cmd[2].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
            rC = self.premap_registers(cmd[2].reg)
        self.out("eor %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_xri(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("lsl %s, %s, #%d" % (rA, rB, cmd[2].value))
        pass

    def translator_xrm(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg, True)
        rB = self.premap_registers(cmd[1].reg, True)
        rC = self.premap_registers(cmd[2].reg, True)
        self.out("eor %s, %s, %s" % (rA, rB, rC))
        pass

    def translator_zes(self, ea, cmd):
        rA = self.premap_registers(cmd[0].reg)
        rB = self.premap_registers(cmd[1].reg)
        if self.auto_extend:
            rA = self.premap_registers(cmd[0].reg)
            rB = self.premap_registers(cmd[1].reg)
        self.out("uxth %s, %s" % (rA, rB))
        pass

    def translator_zew(self, ea, cmd):
        self.out("NOP")
        pass



def main():
    translator = openrisc_translator_arm("outasm.s")
    translator.printAsmHeader()
    for segea in Segments():
        if SegName(segea) == ".plt":
            continue
        attr = GetSegmentAttr(segea,SEGATTR_PERM)
        translator.curIndent = "  "
        translator.printSegHeader(segea,attr)
        translator.curIndent = "    "
        if SegName(segea) == "extern":
            translator.doExternSegTranslation(segea)
        elif attr & SEGPERM_EXEC:
            translator.doCodeSegTranslation(segea)
        else:
            translator.doOtherSegTranslation(segea)
        translator.curIndent = "  "
    translator.curIndent = "  "
    #translator.makeGlobalSegment()
    translator.printAsmFooter()
main()