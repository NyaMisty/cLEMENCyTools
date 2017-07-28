import idaapi
import idc
import ctypes

def convert( data ):
    buf = 0
    remain = 0
    result = bytearray()
    for byte in bytearray( data ):
        buf = buf << 8 | byte
        remain += 8
        if remain >= 9:
            remain -= 9
            t = buf >> remain
            buf -= t << remain
            result.append( t & 0xFF )
            result.append( t >> 8 )
    if remain:
        p = buf << (9-remain)
        result.append( p & 0xFF )
        result.append( p >> 8 )

    return str( result )

def accept_file(li, n):
    '''
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing 
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    '''
    if n:
        return 0
    return 'cLEMENCy binary'

def load_file(li, neflags, format):
    '''
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    '''
    idaapi.set_processor_type( 'cLEMENCy', idaapi.SETPROC_USER | idaapi.SETPROC_FATAL )
    li.seek(0)
    fileLen = li.size()
    data = convert( li.read( fileLen ))
    if len(data) > 0x4000000:
        # program too large
        return 0

    idaname = "ida64" if __EA64__ else "ida"
    if sys.platform == "win32":
        _mod = ctypes.windll[idaname + ".wll"]
    elif sys.platform == "linux2":
        _mod = ctypes.cdll["lib" + idaname + ".so"]
    elif sys.platform == "darwin":
        _mod = ctypes.cdll["lib" + idaname + ".dylib"]
    create_bytearray_linput = _mod.create_bytearray_linput
    create_bytearray_linput.argtypes = (idaapi.POINTER(ctypes.c_ubyte), ctypes.c_int)
    create_bytearray_linput.restype = ctypes.c_int
    bufPointer = idaapi.cast(data, idaapi.POINTER(ctypes.c_ubyte))
    retlinput = create_bytearray_linput(bufPointer,int(fileLen * 8 / 9 * 16 / 8))
    file2base = _mod.file2base
    file2base.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int)
    file2base.restype = ctypes.c_int
    file2base(retlinput,0,0,int(fileLen * 8 / 9), idaapi.FILEREG_PATCHABLE)

    seg = idaapi.segment_t()
    seg.startEA = 0
    seg.endEA = 0x4000000
    # seg.bitness = 1
    idaapi.add_segm_ex( seg, "PROGRAM", "CODE", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x4000000
    seg.endEA = 0x400001e
    idaapi.add_segm_ex( seg, "CLOCKIO", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x4010000
    seg.endEA = 0x4011000
    idaapi.add_segm_ex( seg, "FLAGIO", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x5000000
    seg.endEA = 0x5002000
    idaapi.add_segm_ex( seg, "RDATA", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x5002000
    seg.endEA = 0x5002003
    idaapi.add_segm_ex( seg, "RDATASZ", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x5010000
    seg.endEA = 0x5012000
    idaapi.add_segm_ex( seg, "SDATA", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x5012000
    seg.endEA = 0x5012003
    idaapi.add_segm_ex( seg, "SDATASZ", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x6000000
    seg.endEA = 0x6800000
    idaapi.add_segm_ex( seg, "SHMEM", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x6800000
    seg.endEA = 0x7000000
    idaapi.add_segm_ex( seg, "NVRAM", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x7FFFF00
    seg.endEA = 0x7FFFF1C
    idaapi.add_segm_ex( seg, "IVEC", "RAM", idaapi.ADDSEG_SPARSE )
    seg = idaapi.segment_t()
    seg.startEA = 0x7FFFF80
    seg.endEA = 0x8000000
    idaapi.add_segm_ex( seg, "PROCID", "RAM", idaapi.ADDSEG_SPARSE )
    idaapi.add_entry(0, 0, "_start", True)
    # idc.AutoMark( 0, AU_CODE )
    idaapi.cvar.inf.tribyte_order = idaapi.tbo_213
    return 1
