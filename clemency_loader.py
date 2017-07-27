from idaapi import *
from idc import *

#import pydevd
#pydevd.settrace('localhost', port=15306, stdoutToServer=True, stderrToServer=True,suspend=False,overwrite_prev_trace=True,patch_multiprocessing=True)

def accept_file(li,n):
    if n:
        return 0
    li.seek(0)
    return "Simple cLEMENCy Loader"

def convert_bit(data):
    ret = bytearray()
    x = 0
    n = 0
    for i in data:
        while n >= 9:
            t = x >> n-9
            ret.append(t & 255)
            ret.append(t >> 8)
            x &= (1 << n-9) - 1
            n -= 9
        x = x << 8 | ord(i)
        n += 8
    while n >= 9:
        t = x >> n-9
        ret.append(t & 255)
        ret.append(t >> 8)
        x &= (1 << n-9) - 1
        n -= 9
    return str(ret)

def load_file(li, neflags, format):
    li.seek(0,SEEK_END)
    fileLen = li.tell()
    li.seek(0,SEEK_SET)
    retBuf = li.read(fileLen)
    convertedBuf = convert_bit(retBuf)
    idaname = "ida64" if __EA64__ else "ida"
    if sys.platform == "win32":
        _mod = ctypes.windll[idaname + ".wll"]
    elif sys.platform == "linux2":
        _mod = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        _mod = ctypes.cdll["lib" + idaname + ".dylib"]
    create_bytearray_linput = _mod.create_bytearray_linput
    create_bytearray_linput.argtypes = (POINTER(c_ubyte), ctypes.c_int)
    create_bytearray_linput.restype = ctypes.c_int
    bufPointer = cast(convertedBuf, POINTER(c_ubyte))
    retlinput = create_bytearray_linput(bufPointer,int(fileLen * 8 / 9 * 16 / 8))
    file2base = _mod.file2base
    file2base.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int)
    file2base.restype = ctypes.c_int
    file2base(retlinput,0,0,int(fileLen * 8 / 9),FILEREG_PATCHABLE)
    add_segm(0, 0, int(fileLen * 8 / 9), "FIRMWARE", "CODE")
    #close_linput(retlinput)
    return 1
