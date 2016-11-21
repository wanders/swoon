#!/usr/bin/env python

import argparse
import os
import platform
import pwd
import struct
import subprocess
import sys
import tempfile
import time


EFIINC = os.environ.get('EFIINC', "/usr/include/efi")
EFILIB = os.environ.get('EFILIB', "/usr/lib")
CC = os.environ.get('CC', "gcc")


def assemble(code):
    out = tempfile.NamedTemporaryFile()
    p = subprocess.Popen([CC, "-c", "-x", "assembler", "-", "-o", out.name],
                         stdin=subprocess.PIPE)
    p.communicate(code)

    return out


def compile_c(codepath):
    out = tempfile.NamedTemporaryFile()
    flags = ["-I" + EFIINC, "-I" + EFIINC + "/x86_64", "-fno-stack-protector", "-fpic",
             "-fshort-wchar", "-mno-red-zone", "-Wall",
             "-ffreestanding", "-mno-sse", "-mno-mmx"]
    subprocess.check_call([CC, "-c", codepath, "-o", out.name] + flags)

    return out


def link(input_objects):
    linker_script = EFILIB + "/elf_x86_64_efi.lds"
    crt_path = EFILIB + "/crt0-efi-x86_64.o"
    libs = ["-lefi", "-lgnuefi"]
    lib_path = "/usr/lib"
    out = tempfile.NamedTemporaryFile()
    subprocess.check_call(["ld", "-o", out.name,
                           "-nostdlib", "-znocombreloc",
                           "-T", linker_script,
                           "-shared",
                           "-Bsymbolic", "-L", lib_path, "-L", EFILIB, crt_path] + input_objects + libs)

    return out


def generate_object_from_binary(ident, path):
    CODE = """
        .section .data.{ident},"a"

        .globl _{ident}_data_begin
        .globl _{ident}_data_end

_{ident}_data_begin:
        .incbin "{path}"
_{ident}_data_end:
        .quad 0
"""
    return assemble(CODE.format(ident=ident, path=path))


def generate_creation_message_object(message):
    CODE = """
        .section .data.message,"a"

        .globl _creation_message

_creation_message:
        .byte {bytestr}
        .byte 0x00
        .byte 0x00
"""
    msg16 = message.encode("utf-16le")
    return assemble(CODE.format(bytestr=", ".join(map(str, map(ord, msg16)))))


def at(pos, typ):
    return property(lambda self: typ(self, pos))


class BootProto:
    def __init__(self, f):
        self.buf = f.read(0x4000)
        if len(self.buf) < 0x4000:
            raise ValueError("Couldn't read expected number of bytes, not a kernel?")

        if self.boot_flag != 0xAA55 or self.header != 0x53726448:
            raise ValueError("Not a kernel file")

    def u8(self, off):
        val, = struct.unpack("B", self.buf[off:off + 1])
        return val

    def u16(self, off):
        val, = struct.unpack("H", self.buf[off:off + 2])
        return val

    def u32(self, off):
        val, = struct.unpack("I", self.buf[off:off + 4])
        return val

    def nulstr(self, off):
        res = []
        while ord(self.buf[off]) != 0:
            res.append(self.buf[off])
            off += 1
        return "".join(res)

    boot_flag = at(0x01FE, u16)
    header = at(0x0202, u32)
    version = at(0x206, u16)
    relocatable_kernel = at(0x234, u8)
    kernel_version_off = at(0x20e, u16)
    xloadflags = at(0x236, u16)

    XLOADFLAGS_XLF_EFI_HANDOVER_64 = 1 << 3


def check_kernel(f):
    kern = BootProto(f)

    if kern.version < ((2 << 8) | 11):
        verstr = "%d.%d" % (kern.version >> 8, kern.version & 0xff)
        raise ValueError("Too old boot protocol version (%s)" % verstr)

    if kern.relocatable_kernel == 0:
        raise ValueError("Kernel is not relocatable")

    if not (kern.xloadflags & kern.XLOADFLAGS_XLF_EFI_HANDOVER_64):
        raise ValueError("Kernel does not have efi handover function")

    if not kern.kernel_version_off:
        raise ValueError("Kernel does not have version string")
    return kern.nulstr(kern.kernel_version_off + 0x200)


def make_efi(inputelf, output_path):
    subprocess.check_call(["objcopy",
                           "-j", ".text",
                           "-j", ".sdata",
                           "-j", ".data",
                           "-j", ".dynamic",
                           "-j", ".dynsym",
                           "-j", ".rel",
                           "-j", ".rela",
                           "-j", ".reloc",
                           "--target=efi-app-x86_64",
                           inputelf, output_path])


def build(mainpath, kernelpath, initrdpath, outputpath, msg):
    try:
        kernel_ver = check_kernel(open(kernelpath, "rb"))
    except ValueError as e:
        sys.stderr.write("Problem with kernel: %s\n" % e.message)
        sys.exit(1)

    print("Kernel version: %r" % kernel_ver)

    loader_obj = compile_c(mainpath)
    kernel_obj = generate_object_from_binary("kernel", kernelpath)
    initrd_obj = generate_object_from_binary("initrd", initrdpath)
    messag_obj = generate_creation_message_object(msg)

    temp_elf = link([loader_obj.name, kernel_obj.name,
                     initrd_obj.name, messag_obj.name])

    make_efi(temp_elf.name, outputpath)


def main():
    _, node, _, _, machine, _ = platform.uname()
    if machine != 'x86_64':
        sys.stderr.write("Sorry, only works on x86_64 currently\n")
        sys.exit(1)

    swoondir = os.path.dirname(sys.argv[0])
    mainpath = os.path.join(swoondir, "main.c")

    if not os.access(mainpath, os.R_OK):
        sys.stderr.write("Couldn't access %r\n" % mainpath)
        sys.exit(1)

    p = argparse.ArgumentParser(description='swoon kernel+initrd efi bundler')
    p.add_argument('--kernel', help='kernel image to use', required=True)
    p.add_argument('--initrd', help='initrd image to use', required=True)
    p.add_argument('--output', help='output file path', required=True)

    args = p.parse_args()

    msg = "Generated on {} by {} at {}".format(node,
                                               pwd.getpwuid(os.getuid()).pw_name,
                                               time.strftime("%Y-%m-%d %H:%M:%S"))
    build(mainpath, args.kernel, args.initrd, args.output, msg)

if __name__ == '__main__':
    main()
