import collections

# --------------- ISA Definitions -----------------

CONDSUFFIX = {
	0b0000: 'n',
	0b0001: 'e',
	0b0010: 'l',
	0b0011: 'le',
	0b0100: 'g',
	0b0101; 'ge',
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