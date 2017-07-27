from idaapi import *
from idc import *
from bitarray import bitarray

#import pydevd
#pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True,suspend=False,overwrite_prev_trace=True,patch_multiprocessing=True)

def accept_file(li,n):
    if n:
        return 0
    li.seek(0)
    return "Simple cLEMENCy Loader"

def convent_bit(data):
    buf = ''
    bit_buffer = bitarray()
    bit_buffer.frombytes(data)

    bit_buffer += bitarray('0'*(9-len(bit_buffer)%9))
    for i in range(len(bit_buffer)/9):
        a = bitarray("0"*7) + bit_buffer[i*9:i*9+9]
        buf += a.tobytes()[1] + a.tobytes()[0]

    return buf

def load_file(li, neflags, format):
    li.seek(0,SEEK_END)
    fileLen = li.tell()
    li.seek(0,SEEK_SET)
    retBuf = li.read(fileLen)
    convertedBuf = convent_bit(retBuf)
    _mod = ctypes.WinDLL("ida.wll")
    create_bytearray_linput = _mod.create_bytearray_linput
    create_bytearray_linput.argtypes = (POINTER(c_ubyte), ctypes.c_int)
    create_bytearray_linput.restype = ctypes.c_int
    bufPointer = cast(convertedBuf, POINTER(c_ubyte))
    retlinput = create_bytearray_linput(bufPointer,int(fileLen * 8 / 9 * 16 / 8))
    file2base = _mod.file2base
    file2base.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int)
    file2base.restype = ctypes.c_int
    file2base(retlinput,0,0,int(fileLen * 8 / 9),FILEREG_PATCHABLE)
    file2base(retlinput, 0, 0, int(fileLen * 8 / 9), FILEREG_PATCHABLE)
    add_segm(0, 0, int(fileLen * 8 / 9), "FIRMWARE", "CODE")
    #close_linput(retlinput)
    return 1