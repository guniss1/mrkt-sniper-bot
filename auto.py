#!/usr/bin/env python3
import hashlib
import sys
from pathlib import Path


STUB = bytes.fromhex(
    "534883ec304983f80f740e4983f80774294983f8037443eb6748b86e6f745f77"
    "686974483902755848b874656c697374656448394207742ceb4648b87265766f"
    "6b656400483902741b48b86578706972656400483902740ceb26813a4e2f4100"
    "7410eb1c488d0d4b000000ba02000000eb14488d0d3f000000ba0a000000eb06"
    "4889d14c89c24c8d0500000000410fb6d9ff1500000000488944242084db7410"
    "488d4c2420ff1500000000488b4424204883c4305bc36f6b323032372d31322d"
    "3132"
)

SIGNATURE = [
    0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x49, 0x8B, 0xC0, 0x48, 0x8B, 0xCA,
    0x48, 0x8B, 0xD0, 0x4C, 0x8D, 0x05, None, None, None, None, 0x41, 0x0F,
    0xB6, 0xD9, 0xFF, 0x15, None, None, None, None, 0x48, 0x89, 0x44, 0x24,
    0x20, 0x84, 0xDB, 0x74, 0x10, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xFF, 0x15,
    None, None, None, None, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC4,
    0x30, 0x5B, 0xC3,
]

PREFIX = bytes(x for x in SIGNATURE[:18] if x is not None)
OLD_BANNER = b"      by: @dvraze (dm bug reports / ideya's)"
NEW_BANNER = b"                FREE FOR ALL"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def find_inner_exe(data):
    hits = []
    start = 0
    while True:
        offset = data.find(b"MZ", start)
        if offset < 0:
            break
        if offset + 0x40 <= len(data):
            pe = offset + int.from_bytes(data[offset + 0x3C:offset + 0x40], "little")
            if pe + 4 <= len(data) and data[pe:pe + 4] == b"PE\0\0":
                hits.append(offset)
        start = offset + 1
    if len(hits) < 2:
        raise RuntimeError("inner exe not found")
    return hits[1]


def read_sections(data, base):
    pe = base + int.from_bytes(data[base + 0x3C:base + 0x40], "little")
    count = int.from_bytes(data[pe + 6:pe + 8], "little")
    optional_size = int.from_bytes(data[pe + 20:pe + 22], "little")
    table = pe + 24 + optional_size
    sections = []
    for index in range(count):
        row = table + index * 40
        name = data[row:row + 8].split(b"\0", 1)[0].decode("ascii", "ignore")
        virtual_size = int.from_bytes(data[row + 8:row + 12], "little")
        virtual_address = int.from_bytes(data[row + 12:row + 16], "little")
        raw_size = int.from_bytes(data[row + 16:row + 20], "little")
        raw_pointer = int.from_bytes(data[row + 20:row + 24], "little")
        sections.append({
            "name": name,
            "start": base + raw_pointer,
            "end": base + raw_pointer + raw_size,
            "rva": virtual_address,
            "size": virtual_size,
            "raw_size": raw_size,
            "flags": row + 36,
        })
    return sections


def section_named(sections, name):
    for section in sections:
        if section["name"] == name:
            return section
    raise RuntimeError(name + " section not found")


def file_to_rva(sections, offset):
    for section in sections:
        if section["start"] <= offset < section["end"]:
            return section["rva"] + offset - section["start"]
    raise RuntimeError("offset outside sections")


def read_target(data, sections, offset, opcode_size):
    place = offset + opcode_size
    value = int.from_bytes(data[place:place + 4], "little", signed=True)
    return file_to_rva(sections, offset) + opcode_size + 4 + value


def write_relative(data, offset, next_rva, target_rva):
    value = target_rva - next_rva
    data[offset:offset + 4] = value.to_bytes(4, "little", signed=True)


def matches(data, offset):
    if offset + len(SIGNATURE) > len(data):
        return False
    return all(byte is None or data[offset + index] == byte for index, byte in enumerate(SIGNATURE))


def find_hook(data, text):
    hits = []
    offset = text["start"]
    while True:
        offset = data.find(PREFIX, offset, text["end"])
        if offset < 0:
            break
        if matches(data, offset):
            hits.append(offset)
        offset += 1
    if len(hits) != 1:
        raise RuntimeError("hook not found cleanly")
    return hits[0]


def find_space(data, section, size):
    spaces = []
    offset = section["start"]
    while offset < section["end"]:
        if data[offset] != 0:
            offset += 1
            continue
        start = offset
        while offset < section["end"] and data[offset] == 0:
            offset += 1
        length = offset - start
        if length >= size + 2:
            spaces.append(start + 2)
        elif length >= size:
            spaces.append(start)
    if not spaces:
        raise RuntimeError("space not found")
    return spaces[-1]


def crack(data):
    base = find_inner_exe(data)
    sections = read_sections(data, base)
    text = section_named(sections, ".text")
    rdata = section_named(sections, ".rdata")
    hook = find_hook(data, text)
    space = find_space(data, rdata, len(STUB))
    hook_rva = file_to_rva(sections, hook)
    space_rva = file_to_rva(sections, space)
    object_rva = read_target(data, sections, hook + 0x0F, 3)
    call_one = read_target(data, sections, hook + 0x1A, 2)
    call_two = read_target(data, sections, hook + 0x2E, 2)
    stub = bytearray(STUB)
    write_relative(stub, 0x89, space_rva + 0x8D, object_rva)
    write_relative(stub, 0x93, space_rva + 0x97, call_one)
    write_relative(stub, 0xA7, space_rva + 0xAB, call_two)
    if data[space:space + len(stub)] != b"\0" * len(stub):
        raise RuntimeError("space is not empty")
    data[space:space + len(stub)] = stub
    jump = space_rva - (hook_rva + 5)
    data[hook:hook + 6] = b"\xE9" + jump.to_bytes(4, "little", signed=True) + b"\x90"
    flags = rdata["flags"]
    value = int.from_bytes(data[flags:flags + 4], "little")
    data[flags:flags + 4] = (value | 0x20000000).to_bytes(4, "little")
    banner = NEW_BANNER.ljust(len(OLD_BANNER))
    count = data.count(OLD_BANNER)
    if count:
        data[:] = data.replace(OLD_BANNER, banner)
    return hook, space


def main():
    if len(sys.argv) != 2:
        print("usage: python auto.py mrkt-sniper.exe", file=sys.stderr)
        return 1
    source = Path(sys.argv[1])
    data = bytearray(source.read_bytes())
    hook, space = crack(data)
    output = source.with_name(source.stem + "-cracked" + source.suffix)
    output.write_bytes(data)
    print("saved:", output)
    print("hook:", hex(hook))
    print("stub:", hex(space))
    print("sha256:", sha256(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
