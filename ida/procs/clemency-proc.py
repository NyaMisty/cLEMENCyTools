from idaapi import *

class DecodingError(Exception):
    pass

class MyProcessor(processor_t):
    id = 0x8000 + 8899
    flag = PR_ADJSEGS | PRN_HEX
    cnbits = 9
    dnbits = 9
    psnames = ["clemency"]
    plnames = ["clemency"]
    segreg_size = 0
    instruc_start = 0
    assembler = {
        "flag": AS_NCHRE | ASH_HEXF4 | ASD_DECF1 | ASO_OCTF3 | ASB_BINF2
              | AS_NOTAB,
        "uflag": 0,
        "name": "clemency assembler",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": ".ascii",
        "a_byte": ".byte",
        "a_word": ".word",
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
        "R0",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
        "R16",
        "R17",
        "R18",
        "R19",
        "R20",
        "R21",
        "R22",
        "R23",
        "R24",
        "R25",
        "R26",
        "R27",
        "R28",
        "ST", "RA", "PC", "FL"
    ]

def PROCESSOR_ENTRY():
    return MyProcessor()
