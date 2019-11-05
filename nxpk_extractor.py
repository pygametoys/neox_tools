import os, struct, zlib, io, argparse, csv, ntpath
from tqdm import tqdm
from six import byte2int


class CorruptError(Exception):
    pass


def lz4_uncompress(src):
    """uncompress a block of lz4 data.
    :param bytes src: lz4 compressed data (LZ4 Blocks)
    :returns: uncompressed data
    :rtype: bytearray
    .. seealso:: http://cyan4973.github.io/lz4/lz4_Block_format.html
    """
    src = io.BytesIO(src)

    # if we have the original size, we could pre-allocate the buffer with
    # bytearray(original_size), but then we would have to use indexing
    # instad of .append() and .extend()
    dst = bytearray()
    min_match_len = 4

    def get_length(src, length):
        """get the length of a lz4 variable length integer."""
        if length != 0x0f:
            return length

        while True:
            read_buf = src.read(1)
            if len(read_buf) != 1:
                raise CorruptError("EOF at length read")
            len_part = byte2int(read_buf)

            length += len_part

            if len_part != 0xff:
                break

        return length

    while True:
        # decode a block
        read_buf = src.read(1)
        if len(read_buf) == 0:
            raise CorruptError("EOF at reading literal-len")
        token = byte2int(read_buf)

        literal_len = get_length(src, (token >> 4) & 0x0f)

        # copy the literal to the output buffer
        read_buf = src.read(literal_len)

        if len(read_buf) != literal_len:
            raise CorruptError("not literal data")
        dst.extend(read_buf)

        read_buf = src.read(2)
        if len(read_buf) == 0:
            if token & 0x0f != 0:
                raise CorruptError("EOF, but match-len > 0: %u" % (token % 0x0f, ))
            break

        if len(read_buf) != 2:
            raise CorruptError("premature EOF")

        offset = byte2int([read_buf[0]]) | (byte2int([read_buf[1]]) << 8)

        if offset == 0:
            raise CorruptError("offset can't be 0")

        match_len = get_length(src, (token >> 0) & 0x0f)
        match_len += min_match_len

        # append the sliding window of the previous literals
        for _ in range(match_len):
            dst.append(dst[-offset])

    return dst


def readuint32(f):
    return struct.unpack('I', f.read(4))[0]

def readuint8(f):
    return struct.unpack('B', f.read(1))[0]

def get_ext(data):
    if len(data) == 0:
        return 'none'
    if data[:12] == b'CocosStudio-UI':
        return 'coc'
    elif data[:1] == b'<':
        return 'xml'
    elif data[:1] == b'{':
        return 'json'
    elif data[:3] == b'hit':
        return 'hit'
    elif data[:3] == b'PKM':
        return 'pkm'
    elif data[:3] == b'PVR':
        return 'pvr'
    elif data[:3] == b'DDS':
        return 'dds'
    elif data[1:4] == b'KTX':
        return 'ktx'
    elif data[1:4] == b'PNG':
        return 'png'
    elif data[:4] == bytes([0x34, 0x80, 0xC8, 0xBB]):
        return 'nxm'
    elif data[:4] == bytes([0x14, 0x00, 0x00, 0x00]):
        return 'type1'
    elif data[:4] == bytes([0x04, 0x00, 0x00, 0x00]):
        return 'type2'
    elif data[:4] == bytes([0x00, 0x01, 0x00, 0x00]):
        return 'type3'
    elif data[:4] == b'VANT':
        return 'vant'
    elif data[:4] == b'MDMP':
        return 'mdmp'
    elif data[:4] == b'RGIS':
        return 'rgis'
    elif data[:4] == b'NTRK':
        return 'ntrk'
    elif len(data) < 1000000:
        if b'void' in data or b'main(' in data or b'include' in data or b'float' in data:
            return 'shader'
        if b'technique' in data or b'ifndef' in data:
            return 'shader'
        if b'?xml' in data:
            return 'xml'
        if b'import' in data:
            return 'py'
        if b'1000' in data or b'ssh' in data or b'png' in data or b'tga' in data or b'exit' in data:
            return 'txt'
    return 'dat'

def unpack(opt):
    folder_path = opt.path.replace('.npk', '')
    map_path = opt.path + '.map'

    with open(opt.path, 'rb') as f:
        index_table = []
        index_map = {}
        data = f.read(4)
        assert data == b'NXPK'
        files = readuint32(f)
        var1 = readuint32(f)
        var2 = readuint32(f)
        var3 = readuint32(f)
        mode = 1 if var1 and var3 else 0
        info_size = 0x28 if mode else 0x1c
        index_offset = readuint32(f)
        f.seek(index_offset)
        with io.BytesIO() as tmp:
            if os.path.exists(map_path):
                with open(map_path) as fm:
                    reader = csv.DictReader(fm, ['path', 'sign', 'length', 'hash1', 'ori_length', 'hash2', 'offset'], delimiter='\t')
                    for row in reader:
                        index_map[int(row['sign'])] = row['path']

                    for i in range(files * 28):
                        data = readuint8(f)
                        tmp.write(struct.pack('B', data))
                    tmp.seek(0)
                    for _ in range(files):
                        file_sign = readuint32(tmp)
                        file_offset = readuint32(tmp)
                        file_length = readuint32(tmp)
                        file_original_length = readuint32(tmp)
                        file_hash_1 = readuint32(tmp)
                        file_hash_2 = readuint32(tmp)
                        file_flag = readuint32(tmp)
                        index_table.append((
                            file_offset,
                            file_length,
                            file_original_length,
                            file_flag,
                            index_map[file_sign]
                            ))
            else:
                for i in range(files * 28):
                    data = readuint8(f)
                    tmp.write(struct.pack('B', data))
                tmp.seek(0)
                for _ in range(files):
                    file_sign = readuint32(tmp)
                    file_offset = readuint32(tmp)
                    file_length = readuint32(tmp)
                    file_original_length = readuint32(tmp)
                    file_hash_1 = readuint32(tmp)
                    file_hash_2 = readuint32(tmp)
                    file_flag = readuint32(tmp)
                    index_table.append((
                        file_offset,
                        file_length,
                        file_original_length,
                        file_flag,
                        ))

        for i, item in tqdm(enumerate(index_table)):
            if len(item) > 4:
                file_offset, file_length, file_original_length, file_flag, file_name = item
            else:
                file_name = '{:8}.dat'.format(i)
                file_offset, file_length, file_original_length, file_flag = item
            f.seek(file_offset)
            with io.BytesIO() as tmp:
                for i in range(file_length):
                    data = readuint8(f)
                    tmp.write(struct.pack('B', data))
                tmp.seek(0)
                data = tmp.read()

            if file_flag == 1:
                data = zlib.decompress(data)
            elif file_flag == 2:
                data = lz4_uncompress(data)
            if len(item) == 4:
                ext = get_ext(data)
                file_name = '{:08}.{}'.format(i, ext)
                folder_path_real = folder_path
            else:
                file_name = file_name.replace(ntpath.sep, '/')
                folder_path_real = folder_path + '/' + os.path.dirname(file_name)
                file_name = os.path.basename(file_name)
                _, ext = os.path.splitext(file_name)
            os.makedirs(folder_path_real, exist_ok=True)
            with open(folder_path_real + '/' + file_name , 'wb') as dat:
                dat.write(data)

def get_parser():
    parser = argparse.ArgumentParser(description='NXPK Extractor')
    parser.add_argument('path', type=str)
    opt = parser.parse_args()
    return opt

def main():
    opt = get_parser()
    unpack(opt)


if __name__ == '__main__':
    main()
