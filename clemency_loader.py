from idaapi import *
from idc import *
from bitarray import bitarray

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
    li.seek(0,SEEK_SET)
    fileLen = li.tell()
    retBuf = li.read(fileLen)
    convertedBuf = convent_bit(retBuf)
    retlinput =  create_bytearray_linput(convertedBuf,int(fileLen * 8 / 9 * 16 / 8))
    li.file2base(retlinput,0,0,len(convertedBuf),FILEREG_PATCHABLE)
    close_linput(retlinput)