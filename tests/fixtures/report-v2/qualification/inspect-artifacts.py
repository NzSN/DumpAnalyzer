#!/usr/bin/env python3
"""Read only controlled fixture binaries; emit their identity and exception metadata."""
import hashlib
import json
import math
import struct
import sys
import uuid
from pathlib import Path


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]


def codeview(data):
    assert data[:4] == b'RSDS'
    return {'guid': str(uuid.UUID(bytes_le=data[4:20])).upper(), 'age': u32(data, 20),
            'path': data[24:].split(b'\0', 1)[0].decode('utf-8')}


def pdb_identity(path):
    data = path.read_bytes()
    assert data.startswith(b'Microsoft C/C++ MSF 7.00\r\n')
    block_size, _, _, directory_size, _, block_map = struct.unpack_from('<6I', data, 32)
    count = math.ceil(directory_size / block_size)
    blocks = struct.unpack_from(f'<{count}I', data, block_map * block_size)
    directory = b''.join(data[b * block_size:(b + 1) * block_size] for b in blocks)[:directory_size]
    streams = u32(directory, 0)
    sizes = struct.unpack_from(f'<{streams}I', directory, 4)
    cursor = 4 + streams * 4
    for index, size in enumerate(sizes):
        count = 0 if size == 0xffffffff else math.ceil(size / block_size)
        blocks = struct.unpack_from(f'<{count}I', directory, cursor)
        cursor += count * 4
        if index == 1:
            info = b''.join(data[b * block_size:(b + 1) * block_size] for b in blocks)[:size]
            return {'guid': str(uuid.UUID(bytes_le=info[12:28])).upper(), 'age': u32(info, 8)}
    raise ValueError('PDB Info stream absent')


def pe_identity(path):
    data = path.read_bytes()
    pe = u32(data, 0x3c)
    assert data[pe:pe + 4] == b'PE\0\0'
    sections, optional_size = struct.unpack_from('<H', data, pe + 6)[0], struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from('<H', data, optional)[0] == 0x20b
    table = optional + optional_size
    def file_offset(rva):
        for index in range(sections):
            offset = table + index * 40
            size, address, raw_size, raw = struct.unpack_from('<4I', data, offset + 8)
            if address <= rva < address + max(size, raw_size):
                return raw + rva - address
        raise ValueError(f'RVA not mapped: {rva:x}')
    debug_rva, debug_size = struct.unpack_from('<2I', data, optional + 112 + 6 * 8)
    debug = file_offset(debug_rva)
    for index in range(debug_size // 28):
        entry = debug + index * 28
        if u32(data, entry + 12) == 2:
            size, raw = u32(data, entry + 16), u32(data, entry + 24)
            return {'timestamp': f'0x{u32(data, pe + 8):08x}', 'imageSize': f'0x{u32(data, optional + 56):x}', 'pdb': codeview(data[raw:raw + size])}
    raise ValueError('PE CodeView record absent')


def dump_metadata(path):
    data = path.read_bytes()
    assert data[:4] == b'MDMP'
    count, directory = u32(data, 8), u32(data, 12)
    streams = {u32(data, directory + i * 12): (u32(data, directory + i * 12 + 4), u32(data, directory + i * 12 + 8)) for i in range(count)}
    modules_rva = streams[4][1]
    modules = []
    for index in range(u32(data, modules_rva)):
        module = modules_rva + 4 + index * 108
        name_rva = u32(data, module + 20)
        name = data[name_rva + 4:name_rva + 4 + u32(data, name_rva)].decode('utf-16-le')
        if name.lower().endswith('null-read.exe'):
            cv_size, cv_rva = struct.unpack_from('<2I', data, module + 76)
            modules.append({'path': name, 'base': f'0x{u64(data, module):016x}', 'imageSize': f'0x{u32(data, module + 8):x}', 'timestamp': f'0x{u32(data, module + 16):08x}', 'pdb': codeview(data[cv_rva:cv_rva + cv_size])})
    exception_rva = streams[6][1]
    context_size, context_rva = struct.unpack_from('<2I', data, exception_rva + 160)
    context = data[context_rva:context_rva + context_size]
    parameters = [f'0x{u64(data, exception_rva + 40 + i * 8):016x}' for i in range(u32(data, exception_rva + 32))]
    return {'fixtureModules': modules, 'exception': {'threadId': u32(data, exception_rva), 'code': f'0x{u32(data, exception_rva + 8):08x}', 'flags': f'0x{u32(data, exception_rva + 12):08x}', 'address': f'0x{u64(data, exception_rva + 24):016x}', 'parameters': parameters, 'contextSize': context_size, 'registers': {name: f'0x{u64(context, offset):016x}' for name, offset in [('rax', 120), ('rcx', 128), ('rsp', 152), ('rip', 248)]}}}


def artifact(path):
    data = path.read_bytes()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


root = Path(sys.argv[1])
output = {'dump': artifact(root / 'null-read.dmp'), 'minidump': dump_metadata(root / 'null-read.dmp'), 'builds': {}}
for variant in ['matching', 'mismatched']:
    exe, pdb = root / variant / 'null-read.exe', root / variant / 'null-read.pdb'
    pe, info = pe_identity(exe), pdb_identity(pdb)
    assert pe['pdb']['guid'] == info['guid'] and pe['pdb']['age'] == info['age']
    output['builds'][variant] = {'exe': artifact(exe), 'pdb': {**artifact(pdb), **info}, 'image': pe}
expected = output['minidump']['fixtureModules'][0]['pdb']
assert expected['guid'] == output['builds']['matching']['pdb']['guid']
assert expected['age'] == output['builds']['matching']['pdb']['age']
assert expected['guid'] != output['builds']['mismatched']['pdb']['guid']
assert output['minidump']['exception']['parameters'] == ['0x0000000000000000', '0x0000000000000000']
assert output['minidump']['exception']['registers']['rax'] == '0x0000000000000000'
print(json.dumps(output, indent=2))
