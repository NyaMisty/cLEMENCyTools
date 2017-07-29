# coding=utf-8

from idaapi import *
from idc import *
import collections

# --------------- ISA Definitions -----------------

CONDSUFFIX = {
	0b0000: 'n',
	0b0001: 'e',
	0b0010: 'l',
	0b0011: 'le',
	0b0100: 'g',
	0b0101: 'ge',
	0b0110: 'no',
	0b0111: 'o',
	0b1000: 'ns',
	0b1001: 's',
	0b1010: 'sl',
	0b1011: 'sle',
	0b1100: 'sg',
	0b1101: 'sge',
	0b1111: '', # Always
}

ISAOperand = collections.namedtuple('ISAOperand', ['name', 'start', 'width'])
# ISAInstruction = collections.namedtuple('ISAInstruction', ['size_in_bytes', 'name', 'operands', 'opcode_bits', 'opcode', 'subopcode', 'subopcode_start', 'subopcode_bits', 'update_flag'])
class ISAInstruction(object):
	pass

def ParseISADefinitionLine(ln):
    segs = ln.split(' ')
    instrlen = segs[-1]
    assert instrlen.endswith('b')

    result = ISAInstruction()
    result.name = segs[0].lower()
    result.size_in_bytes = int(instrlen[:-1])
    result.opcode = int(segs[1].split('=')[1], 16)
    result.opcode_bits = int(segs[1].split('=')[0].split('-')[1]) + 1
    result.subopcode = None
    result.update_flag = None
    result.operands = []
    for seg in segs[2:-1]:
    	br, name = seg.split('=')
    	if '-' not in br: br = br + '-' + br
    	start, end = map(int, br.split('-'))
    	width = end-start + 1
    	if name.startswith('0x'):
    		assert result.subopcode is None, ln
    		result.subopcode = int(name, 16)
    		result.subopcode_start = start
    		result.subopcode_bits = width
    	elif name == 'UF':
    		assert result.update_flag == None
    		result.update_flag = start
    		assert width == 1
    	else:
    		result.operands.append(ISAOperand(name, start, width))
    return result

#with open('isa.txt') as fp:
#    ISA_DEF = map(ParseISADefinitionLine, fp.read().strip().split('\n'))

ISA_DEF_STR = '''AD 0-6=0x0 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ADC 0-6=0x20 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ADCI 0-6=0x20 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ADCIM 0-6=0x22 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ADCM 0-6=0x22 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ADF 0-6=0x1 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ADFM 0-6=0x3 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ADI 0-6=0x0 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ADIM 0-6=0x2 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ADM 0-6=0x2 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
AN 0-6=0x14 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ANI 0-6=0x14 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ANM 0-6=0x16 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
B 0-5=0x30 6-9=Condition 10-26=Offset 3b
BF 0-8=0x14c 9-13=rA 14-18=rB 19-25=0x40 26=UF 3b
BFM 0-8=0x14e 9-13=rA 14-18=rB 19-25=0x40 26=UF 3b
BR 0-5=0x32 6-9=Condition 10-14=rA 15-17=0x0 2b
BRA 0-8=0x1c4 9-35=Location 4b
BRR 0-8=0x1c0 9-35=Offset 4b
C 0-5=0x35 6-9=Condition 10-26=Offset 3b
CAA 0-8=0x1cc 9-35=Location 4b
CAR 0-8=0x1c8 9-35=Offset 4b
CM 0-7=0xb8 8-12=rA 13-17=rB 2b
CMF 0-7=0xba 8-12=rA 13-17=rB 2b
CMFM 0-7=0xbe 8-12=rA 13-17=rB 2b
CMI 0-7=0xb9 8-12=rA 13-26=imm 3b
CMIM 0-7=0xbd 8-12=rA 13-26=imm 3b
CMM 0-7=0xbc 8-12=rA 13-17=rB 2b
CR 0-5=0x37 6-9=Condition 10-14=rA 15-17=0x0 2b
DBRK 0-17=0x3ffff 2b
DI 0-11=0xa05 12-16=rA 17=0x0 2b
DMT 0-6=0x34 7-11=rA 12-16=rB 17-21=rC 22-26=0x0 3b
DV 0-6=0xc 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
DVF 0-6=0xd 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
DVFM 0-6=0xf 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
DVI 0-6=0xc 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
DVIM 0-6=0xe 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
DVIS 0-6=0xc 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
DVISM 0-6=0xe 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
DVM 0-6=0xe 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
DVS 0-6=0xc 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
DVSM 0-6=0xe 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
EI 0-11=0xa04 12-16=rA 17=0x0 2b
FTI 0-8=0x145 9-13=rA 14-18=rB 19-26=0x0 3b
FTIM 0-8=0x147 9-13=rA 14-18=rB 19-26=0x0 3b
HT 0-17=0x280c0 2b
IR 0-17=0x28040 2b
ITF 0-8=0x144 9-13=rA 14-18=rB 19-26=0x0 3b
ITFM 0-8=0x146 9-13=rA 14-18=rB 19-26=0x0 3b
LDS 0-6=0x54 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
LDT 0-6=0x56 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
LDW 0-6=0x55 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
MD 0-6=0x10 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MDF 0-6=0x11 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MDFM 0-6=0x13 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MDI 0-6=0x10 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
MDIM 0-6=0x12 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
MDIS 0-6=0x10 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
MDISM 0-6=0x12 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
MDM 0-6=0x12 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MDS 0-6=0x10 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
MDSM 0-6=0x12 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
MH 0-4=0x11 5-9=rA 10-26=imm 3b
ML 0-4=0x12 5-9=rA 10-26=imm 3b
MS 0-4=0x13 5-9=rA 10-26=immS 3b
MU 0-6=0x8 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MUF 0-6=0x9 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MUFM 0-6=0xb 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MUI 0-6=0x8 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
MUIM 0-6=0xa 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
MUIS 0-6=0x8 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
MUISM 0-6=0xa 7-11=rA 12-16=rB 17-23=immS 24-25=0x3 26=UF 3b
MUM 0-6=0xa 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
MUS 0-6=0x8 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
MUSM 0-6=0xa 7-11=rA 12-16=rB 17-21=rC 22-25=0x2 26=UF 3b
NG 0-8=0x14c 9-13=rA 14-18=rB 19-25=0x0 26=UF 3b
NGF 0-8=0x14d 9-13=rA 14-18=rB 19-25=0x0 26=UF 3b
NGFM 0-8=0x14f 9-13=rA 14-18=rB 19-25=0x0 26=UF 3b
NGM 0-8=0x14e 9-13=rA 14-18=rB 19-25=0x0 26=UF 3b
NT 0-8=0x14c 9-13=rA 14-18=rB 19-25=0x20 26=UF 3b
NTM 0-8=0x14e 9-13=rA 14-18=rB 19-25=0x20 26=UF 3b
OR 0-6=0x18 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ORI 0-6=0x18 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
ORM 0-6=0x1a 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
RE 0-17=0x28000 2b
RF 0-11=0xa0c 12-16=rA 17=0x0 2b
RL 0-6=0x30 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
RLI 0-6=0x40 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
RLIM 0-6=0x42 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
RLM 0-6=0x32 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
RMP 0-6=0x52 7-11=rA 12-16=rB 17-26=0x0 3b
RND 0-8=0x14c 9-13=rA 14-25=0x60 26=UF 3b
RNDM 0-8=0x14e 9-13=rA 14-25=0x60 26=UF 3b
RR 0-6=0x31 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
RRI 0-6=0x41 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
RRIM 0-6=0x43 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
RRM 0-6=0x33 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SA 0-6=0x2d 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SAI 0-6=0x3d 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SAIM 0-6=0x3f 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SAM 0-6=0x2f 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SB 0-6=0x4 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SBC 0-6=0x24 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SBCI 0-6=0x24 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
SBCIM 0-6=0x26 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
SBCM 0-6=0x26 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SBF 0-6=0x5 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SBFM 0-6=0x7 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SBI 0-6=0x4 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
SBIM 0-6=0x6 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
SBM 0-6=0x6 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SES 0-11=0xa07 12-16=rA 17-21=rB 22-26=0x0 3b
SEW 0-11=0xa08 12-16=rA 17-21=rB 22-26=0x0 3b
SF 0-11=0xa0b 12-16=rA 17=0x0 2b
SL 0-6=0x28 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SLI 0-6=0x38 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SLIM 0-6=0x3a 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SLM 0-6=0x2a 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SMP 0-6=0x52 7-11=rA 12-16=rB 17=0x1 18-19=Memory_Flags 3b
SR 0-6=0x29 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
SRI 0-6=0x39 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SRIM 0-6=0x3b 7-11=rA 12-16=rB 17-23=imm 24-25=0x0 26=UF 3b
SRM 0-6=0x2b 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
STS 0-6=0x58 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
STT 0-6=0x5a 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
STW 0-6=0x59 7-11=rA 12-16=rB 17-21=Reg_Count 22-23=Adj_rB 24-50=mem_off 51-53=0x0 6b
WT 0-17=0x28080 2b
XR 0-6=0x1c 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
XRI 0-6=0x1c 7-11=rA 12-16=rB 17-23=imm 24-25=0x1 26=UF 3b
XRM 0-6=0x1e 7-11=rA 12-16=rB 17-21=rC 22-25=0x0 26=UF 3b
ZES 0-11=0xa09 12-16=rA 17-21=rB 22-26=0x0 3b
ZEW 0-11=0xa0a 12-16=rA 17-21=rB 22-26=0x0 3b'''

ISA_DEF = map(ParseISADefinitionLine, ISA_DEF_STR.strip().split('\n'))

ISA_DEF.sort(key=lambda x: x.opcode_bits)

ISA_DEF_GROUPED_BY_OPLEN = collections.defaultdict(lambda: collections.defaultdict(lambda: []))
for rins in ISA_DEF:
	ISA_DEF_GROUPED_BY_OPLEN[rins.opcode_bits][rins.opcode].append(rins)
# -------------------------------------------------

# {'name': 'lui', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'lui rd,imm'},
# 在这里按照上面的格式添加指令~~
IDA_INSTR_DEF = [
    {'name': 'ad', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'AD RA, RB, RC'},
    {'name': 'adc', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADC RA, RB, RC + Carray_Bit'},
    {'name': 'adci', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADCI RA, RB, IMM'},
    {'name': 'adcim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ADCIM RA, RB, IMM (54bit-reg'},
    {'name': 'adcm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'ra:ra+1 <- rb:rb+1 + rc:rc+1 + C_B'},
    {'name': 'adf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'add float num'},
    {'name': 'adfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': '54bit float number add(ra:ra+1 <- rb:rb+1 + rc:rc+1)'},
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
    {'name': 'csge', 'feature': CF_CALL | CF_USE1, 'cmt': 'signed >='},
    {'name': 'caa', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Absolute   RA=PC+4 pc = location'},
    {'name': 'car', 'feature': CF_CALL | CF_USE1, 'cmt': 'Call Relative   CAR Offset'},
    {'name': 'cm', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare  CM rA, rB'},
    {'name': 'cmf', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Floating Point  CMF rA, rB'},
    {'name': 'cmfm', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Compare Floating Point Multi Reg CMFM rA, rB'},
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
    {'name': 'di', 'feature': CF_USE1, 'cmt': 'Disable Interrupts   DI rA'},
    {'name': 'dmt', 'feature': CF_USE1 | CF_USE2 | CF_USE3,
     'cmt': 'copy data from [rb + p] to [ra + p] for rc times  DMT rA, rB, rC'},
    {'name': 'dv', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide   DV rA, rB, rC'},
    {'name': 'dvf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Divide Floating Point   DVF rA, rB, rC'},
    {'name': 'dvfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Divide Floating Point Multi Reg    DVFM rA, rB, rC'},
    {'name': 'dvi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Immediate    DVI rA, rB, IMM'},
    {'name': 'dvim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Divide Immediate Multi Reg DVIM rA, rB, IMM'},
    {'name': 'dvis', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Divide Immediate Signed    DVIS rA, rB, IMM'},
    {'name': 'dvism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Divide Immediate Signed Multi Reg  DVISM rA, rB, IMM'},
    {'name': 'dvm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Multi Reg    DVM rA, rB, rC'},
    {'name': 'dvs', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Divide Signed   DVS rA, rB, rC'},
    {'name': 'dvsm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Divide Signed Multi Reg    DVSM rA, rB, rC'},
    {'name': 'ei', 'feature': CF_USE1, 'cmt': 'Enable Interrupts    EI rA'},
    #
    {'name': 'fti', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer ra <- (int)rb ;FTI rA, rB'},
    {'name': 'ftim', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Float to Integer Multi Reg FTIM rA, rB'},
    {'name': 'ht', 'feature': CF_STOP, 'cmt': 'Halt HT'},
    {'name': 'ir', 'feature': CF_STOP, 'cmt': 'Interrupt Return IR'},
    {'name': 'itf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float    ITF rA, rB'},
    {'name': 'itfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Integer to Float Multi Reg ITFM rA, rB'},
    # load
    {'name': 'lds', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Single    LDSm rA, [rB + Offset, RegCount] (rB not modified)'},
    {'name': 'ldt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Tri    LDTm rA, [rB + Offset, RegCount] (rB not modified)'},
    {'name': 'ldw', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Word   LDWm rA, [rB + Offset, RegCount] (rB not modified)'},

    {'name': 'ldsi', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Single    LDSm rA, [rB + Offset, RegCount] (rB substracted)'},
    {'name': 'ldti', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Tri    LDTm rA, [rB + Offset, RegCount] (rB substracted)'},
    {'name': 'ldwi', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Word   LDWm rA, [rB + Offset, RegCount] (rB substracted)'},

    {'name': 'ldsd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Single    LDSm rA, [rB + Offset, RegCount] (rB added)'},
    {'name': 'ldtd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Tri    LDTm rA, [rB + Offset, RegCount] (rB added)'},
    {'name': 'ldwd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Load Word   LDWm rA, [rB + Offset, RegCount] (rB added)'},

    {'name': 'md', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus  MD rA, rB, rC'},
    {'name': 'mdf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Modulus Floating Point  MDF rA, rB, rC'},
    {'name': 'mdfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Modulus Floating Point Multi Reg   MDFM rA, rB, rC'},
    {'name': 'mdi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Immediate   MDI rA, rB, IMM'},
    {'name': 'mdim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Modulus Immediate Multi Reg    MDIM rA, rB, IMM'},
    {'name': 'mdis', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Modulus Immediate Signed   MDIS rA, rB, IMM'},
    {'name': 'mdism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Modulus Immediate Signed Multi Reg MDISM rA, rB, IMM'},
    {'name': 'mdm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Multi Reg   MDM rA, rB, rC'},
    {'name': 'mds', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Modulus Signed  MDS rA, rB, rC'},
    {'name': 'mdsm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Modulus Signed Multi Reg   MDSM rA, rB, rC'},

    #
    {'name': 'mh', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move High    MH rA, IMM'},
    {'name': 'ml', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low ML rA, IMM'},
    {'name': 'ms', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Move Low Signed  MS rA, IMM'},
    {'name': 'mu', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply MU rA, rB, rC'},
    {'name': 'muf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Floating Point MUF rA, rB, rC'},
    {'name': 'mufm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Floating Point Multi Reg  MUFM rA, rB, rC'},
    {'name': 'mui', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Immediate  MUI rA, rB, IMM'},
    {'name': 'muim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Immediate Multi Reg   MUIM rA, rB, IMM'},
    {'name': 'muis', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Immediate Signed  MUIS rA, rB, IMM'},
    {'name': 'muism', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Immediate Signed Multi Reg    MUISM rA, rB, IMM'},
    {'name': 'mum', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Multi Reg  MUM rA, rB, rC'},
    {'name': 'mus', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Multiply Signed MUS rA, rB, rC'},
    {'name': 'musm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Multiply Signed Multi Reg  MUSM rA, rB, rC'},
    #
    {'name': 'ng', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate   NG rA, rB'},
    {'name': 'ngf', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Floating Point   NGF rA, rB'},
    {'name': 'ngfm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1,
     'cmt': 'Negate Floating Point Multi Reg    NGFM rA, rB'},
    {'name': 'ngm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Negate Multi Reg    NGM rA, rB'},
    {'name': 'nt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not  NT rA, rB'},
    {'name': 'ntm', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Not Multi Reg   NTM rA, rB'},
    # or
    {'name': 'or', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or   OR rA, rB, rC'},
    {'name': 'ori', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or Immediate    ORI rA, rB, IMM'},
    {'name': 'orm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Or Multi Reg    ORM rA, rB, rC'},
    {'name': 're', 'feature': CF_STOP, 'cmt': 'Return   RE'},
    {'name': 'rf', 'feature': CF_USE1 | CF_CHG1, 'cmt': 'Read Flags   RF rA'},
    {'name': 'rl', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Left  RL rA, rB, rC'},
    {'name': 'rli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Left Immediate   RLI rA, rB, IMM'},
    {'name': 'rlim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Left Immediate Multi Reg    RLIM rA, rB, IMM'},
    {'name': 'rlm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Left Multi Reg   RLM rA, rB, rC'},
    {'name': 'rmp', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Read Memory Protection  RMP rA, rB'},
    {'name': 'rnd', 'feature': CF_USE1 | CF_CHG1, 'cmt': 'Random  RND rA'},
    {'name': 'rndm', 'feature': CF_USE1 | CF_CHG1, 'cmt': 'Random Multi Reg   RNDM rA'},
    {'name': 'rr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Rotate Right RR rA, rB, rC'},
    {'name': 'rri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Right Immediate  RRI rA, rB, IMM'},
    {'name': 'rrim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Right Immediate Multi Reg   RRIM rA, rB, rC'},
    {'name': 'rrm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Rotate Right Multi Reg  RRM rA, rB, rC'},
    {'name': 'sa', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Arithemetic Right  SA rA, rB, rC'},
    {'name': 'sai', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Arithemetic Right Immediate  SAI rA, rB, IMM'},
    {'name': 'saim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Arithemetic Right Immediate Multi Reg    SAIM rA, rB, IMM'},
    {'name': 'sam', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Arithemetic Right Multi Reg  SAM rA, rB, rC'},
    {'name': 'sb', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract SB rA, rB, rC'},
    {'name': 'sbc', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract With Carry SBC rA, rB, rC'},
    {'name': 'sbci', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Immediate With Carry  SBCI rA, rB, IMM'},
    {'name': 'sbcim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Immediate Multi Reg With Carry    SBCIM rA, rB, IMM'},
    {'name': 'sbcm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Multi Reg With Carry  SBCM rA, rB, rC'},
    {'name': 'sbf', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Floating Point SBF rA, rB, rC'},
    {'name': 'sbfm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Floating Point Multi Reg  SBFM rA, rB, rC'},
    {'name': 'sbi', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract Immediate  SBI rA, rB, IMM'},
    {'name': 'sbim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Subtract Immediate Multi Reg   SBIM rA, rB, IMM'},
    {'name': 'sbm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Subtract Multi Reg  SBM rA, rB, rC'},
    {'name': 'ses', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Sign Extend Single  SES rA, rB'},
    {'name': 'sew', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Sign Extend Word    SEW rA, rB'},
    {'name': 'sf', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Set Flags    SF rA'},
    {'name': 'sl', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Shift Left   SL rA, rB, rC'},
    {'name': 'sli', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Left Immediate    SLI rA, rB, IMM'},
    {'name': 'slim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Left Immediate Multi Reg SLIM rA, rB, IMM'},
    {'name': 'slm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Left Multi Reg    SLM rA, rB, rC'},
    {'name': 'smp', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Set Memory Protection   SMP rA, rB, FLAGS'},
    {'name': 'sr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Shift Right  SR rA, rB, rC'},
    {'name': 'sri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Right Immediate   SRI rA, rB, IMM'},
    {'name': 'srim', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Right Immediate Multi Reg    SRIM rA, rB, IMM'},
    {'name': 'srm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1,
     'cmt': 'Shift Right Multi Reg   SRM rA, rB, rC'},

    #
    {'name': 'sts', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Single   STSm rA, [rB + Offset, RegCount] (rB not modified)'},
    {'name': 'stt', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Tri   STTm rA, [rB + Offset, RegCount] (rB not modified)'},
    {'name': 'stw', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Word STWm rA, [rB + Offset, RegCount] (rB not modified)'},

    {'name': 'stsd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Single   STSm rA, [rB + Offset, RegCount] (rB substracted)'},
    {'name': 'sttd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Tri   STTm rA, [rB + Offset, RegCount] (rB substracted)'},
    {'name': 'stwd', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Word STWm rA, [rB + Offset, RegCount] (rB substracted)'},

    {'name': 'stsi', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Single   STSm rA, [rB + Offset, RegCount] (rB added)'},
    {'name': 'stti', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Tri   STTm rA, [rB + Offset, RegCount] (rB added)'},
    {'name': 'stwi', 'feature': CF_USE1 | CF_USE2 | CF_CHG1 | CF_CHG2,
     'cmt': 'Store Word STWm rA, [rB + Offset, RegCount] (rB added)'},
    #
    {'name': 'wt', 'feature': 0, 'cmt': 'Wait WT'},
    {'name': 'xr', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor  XR rA, rB, rC'},
    {'name': 'xri', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor Immediate   XRI rA, rB, IMM'},
    {'name': 'xrm', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CHG1, 'cmt': 'Xor Multi Reg   XRM rA, rB, rC'},
    {'name': 'zes', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Zero Extend Single  ZES rA, rB'},
    {'name': 'zew', 'feature': CF_USE1 | CF_USE2 | CF_CHG1, 'cmt': 'Zero Extend Word    ZEW rA, rB'}
]
