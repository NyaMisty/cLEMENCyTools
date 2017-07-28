import idaapi
import idc

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
        result.append( remain )

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
    data = convert( li.read( li.size() ))
    if len(data) > 0x4000000:
        # program too large
        return 0

    seg = idaapi.segment_t()
    seg.startEA = 0
    seg.endEA = 0x3FFFFFF
    # seg.bitness = 1
    idaapi.add_segm_ex( seg, "PROGRAM", "RAM", idaapi.ADDSEG_SPARSE )
    idaapi.mem2base( data, 0, len(data) )
    # idc.AutoMark( 0, AU_CODE )

    return 1
