import ctypes
import collections

# ---------------- Dirty Constants -----------------
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    m = 1 << (b - 1)
    x = x & ((1 << b) - 1)
    return (x ^ m) - m

#def toInt(x):
#    return ctypes.c_int(x & 0xffffffff).value

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
# -------------------------------------------------

# --------------- ISA Definitions -----------------

ISAOperand = collections.namedtuple('ISAOperand', ['name', 'start', 'width'])
ISAInstruction = collections.namedtuple('ISAInstruction', ['size_in_bytes', 'name', 'operands', 'opcode_bits', 'opcode', 'subopcode', 'subopcode_start', 'subopcode_bits', 'update_flag'])

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
    		assert result.subopcode is None
    		result.subopcode = int(name, 16)
    		result.subopcode_start = start
    		result.subopcode_bits = width
    	elif name == 'UF':
    		assert result.update_flag = None
    		result.update_flag = start
    		assert width == 1
    	else:
    		result.operands.append(ISAOperand(name, start, width))
    return result


with open('isa.txt') as fp:
    ISA_DEF = map(ParseISADefinitionLine, fp.read().strip())

ISA_DEF.sort(key=lambda x: x.opcode_bits)
# -------------------------------------------------