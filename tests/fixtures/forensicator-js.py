#!/usr/bin/python3
"""Generate a synthetic Windows x64 minidump with physical V8/JIT frames.

Uses the V8 14.6 cage layouts exercised by NzSN/Forensicator's Test/Spec.lean.
No private capture or live JavaScript process is involved. --without-heap
keeps the same frame markers but removes the metadata needed for names.
"""
from pathlib import Path
import struct
import sys


def capture(with_heap=True):
    cage = 0x100000000
    regions = {}

    def region(address, size=0x100):
        regions[address] = bytearray(size)
        return regions[address]

    def u32(data, offset, value):
        struct.pack_into("<I", data, offset, value)

    def u64(data, offset, value):
        struct.pack_into("<Q", data, offset, value)

    maps = region(cage, 0x400)
    for offset, kind in [(0x108, 0x08), (0x208, 0x83), (0x288, 0x812),
                         (0x2C8, 0x120), (0x308, 0x11E), (0x348, 0xA6)]:
        u32(maps, offset, kind)

    def string(offset, value):
        data = region(cage + offset)
        u32(data, 0, 0x101)
        u32(data, 8, len(value))
        data[12:12 + len(value)] = value.encode()

    string(0xC0000, "plainFunction")
    string(0xC2000, "optimizedFunction")
    string(0x140000, "fixture.js")
    for index in [0, 1]:
        delta = index * 0x1000
        function = region(cage + 0x40000 + delta)
        for offset, value in [(0, 0x281), (12, index << 16), (16, 0x80001 + delta),
                              (20, 0x180001), (24, 0x50001 + delta)]:
            u32(function, offset, value)
        shared = region(cage + 0x80000 + delta)
        for offset, value in [(0, 0x2C1), (12, 0xC0001 + delta), (20, 0x100001)]:
            u32(shared, offset, value)
        cell = region(cage + 0x50000 + delta)
        u32(cell, 4, 0x60001 + delta)
        feedback = region(cage + 0x60000 + delta)
        for offset, value in [(0, 0x201), (4, 3), (16, 0x80001 + delta),
                              (28, 0), (32, 0x70001), (36, 84)]:
            u32(feedback, offset, value)
    scope = region(cage + 0xC1000)
    for offset, value in [(0, 0x301), (4, 0x1000), (16, 42 * 2), (24, 0xC2001)]:
        u32(scope, offset, value)
    script = region(cage + 0x100000)
    for offset, value in [(0, 0x341), (8, 0x140001), (28, 0x150001)]:
        u32(script, offset, value)
    lines = region(cage + 0x150000)
    for offset, value in [(4, 3 * 2), (8, 20 * 2), (12, 60 * 2), (16, 100 * 2)]:
        u32(lines, offset, value)
    region(cage + 0x180000)
    region(cage + 0x70000)
    # Two JSDT entries pointing into the range of the observed frame PCs.
    dispatch = region(0x500000000)
    for offset, value in [(0, 0x7FFA1000), (8, 0x600000000),
                         (16, 0x200001000), (24, 0x600000100)]:
        u64(dispatch, offset, value)
    stack = region(0xF000, 0x2000)
    for fp, marker, function in [(0x10000, 6, cage + 0x41001),
                                 (0x10080, 3, cage + 0x40001)]:
        for offset, value in [(-24, marker), (-16, function), (-8, cage + 0x180001)]:
            u64(stack, fp - 0xF000 + offset, value)
    u64(stack, 0x1000, 0x10080)
    u64(stack, 0x1008, 0x7FFA1000)
    if not with_heap:
        regions = {0xF000: stack}

    streams = []
    output = bytearray(32 + 6 * 12)

    def append(data):
        rva = len(output)
        output.extend(data)
        return rva

    def stream(kind, data):
        streams.append((kind, len(data), append(data)))

    locations = {address: append(data) for address, data in regions.items()}

    def context(rip, rsp, rbp):
        data = bytearray(1232)
        u32(data, 0x30, 0x00100003)
        for offset, value in [(0x98, rsp), (0xA0, rbp), (0xF8, rip)]:
            u64(data, offset, value)
        return append(data)

    thread_context = context(0x7FFA1000, 0x10010, 0x10080)
    exception_context = context(0x200001010, 0xFF00, 0x10000)
    system = bytearray(56)
    struct.pack_into("<H", system, 0, 9)
    u32(system, 8, 10)
    u32(system, 20, 2)
    stream(7, system)
    threads = bytearray(52)
    u32(threads, 0, 1)
    u32(threads, 4, 42)
    u64(threads, 28, 0xF000)
    for offset, value in [(36, len(stack)), (40, locations[0xF000]),
                          (44, 1232), (48, thread_context)]:
        u32(threads, offset, value)
    stream(3, threads)
    name = "electron.exe".encode("utf-16-le")
    name_rva = append(struct.pack("<I", len(name)) + name)
    modules = bytearray(112)
    u32(modules, 0, 1)
    u64(modules, 4, 0x7FFA0000)
    u32(modules, 12, 0x10000)
    u32(modules, 24, name_rva)
    stream(4, modules)
    memory = struct.pack("<I", len(regions)) + b"".join(
        struct.pack("<QII", address, len(data), locations[address]) for address, data in regions.items())
    stream(5, memory)
    exception = bytearray(168)
    u32(exception, 0, 42)
    u32(exception, 8, 0xC0000005)
    u64(exception, 24, 0x200001010)
    u32(exception, 160, 1232)
    u32(exception, 164, exception_context)
    stream(6, exception)
    stream(10, b"ver=41.0.0\0v8_ro_space_firstpage_address=0x100000000\0")
    struct.pack_into("<IIIIIIQ", output, 0, 0x504D444D, 0xA793, len(streams), 32, 0, 0, 0)
    for index, descriptor in enumerate(streams):
        struct.pack_into("<III", output, 32 + index * 12, *descriptor)
    return output


if __name__ == "__main__":
    Path(sys.argv[1]).write_bytes(capture("--without-heap" not in sys.argv[2:]))
