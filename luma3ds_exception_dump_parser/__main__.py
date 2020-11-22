#!/usr/bin/env python
# Requires Python >= 3.2 or >= 2.7

#   This file is part of Luma3DS
#   Copyright (C) 2016-2020 Aurora Wright, TuxSH
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#   Additional Terms 7.b of GPLv3 applies to this file: Requiring preservation of specified
#   reasonable legal notices or author attributions in that material or in the Appropriate Legal
#   Notices displayed by works containing it.

__author__    = "TuxSH"
__copyright__ = "Copyright (c) 2016-2020 TuxSH"
__license__   = "GPLv3"
__version__   = "v1.2"

"""
Parses Luma3DS exception dumps
"""

import argparse
from struct import unpack_from

import os
import subprocess

# Source of hexdump: https://gist.github.com/ImmortalPC/c340564823f283fe530b
# Credits for hexdump go to the original authors
# Slightly edited by TuxSH

def hexdump(addr, src, length=16, sep='.' ):
    '''
    @brief Return {src} in hex dump.
    @param[in] length   {Int} Nb Bytes by row.
    @param[in] sep      {Char} For the text part, {sep} will be used for non ASCII char.
    @return {Str} The hexdump
    @note Full support for python2 and python3 !
    '''
    result = []

    # Python3 support
    try:
        xrange(0,1)
    except NameError:
        xrange = range

    for i in xrange(0, len(src), length):
        subSrc = src[i:i+length]
        hexa = ''
        isMiddle = False
        for h in xrange(0,len(subSrc)):
            if h == length/2:
                hexa += ' '
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace('0x','')
            if len(h) == 1:
                h = '0'+h
            hexa += h+' '
        hexa = hexa.strip(' ')
        text = ''
        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep
        result.append(('%08x:  %-'+str(length*(2+1)+1)+'s  |%s|') % (addr + i, hexa, text))

    return '\n'.join(result)


def makeRegisterLine(A, rA, B, rB):
    return "{0:<15}{1:<20}{2:<15}{3:<20}".format(A, "{0:08x}".format(rA), B, "{0:08x}".format(rB))

handledExceptionNames = ("FIQ", "undefined instruction", "prefetch abort", "data abort")
registerNames = tuple("r{0}".format(i) for i in range(13)) + ("sp", "lr", "pc", "cpsr") + ("dfsr", "ifsr", "far") + ("fpexc", "fpinst", "fpinst2")
svcBreakReasons = ("(svcBreak: panic)", "(svcBreak: assertion failed)", "(svcBreak: user-related)")
faultStatusSources = {
    0b1:'Alignment', 0b100:'Instruction cache maintenance operation fault',
    0b1100:'External Abort on translation - First-level', 0b1110:'External Abort on translation - Second-level',
    0b101:'Translation - Section', 0b111:'Translation - Page', 0b11:'Access bit - Section', 0b110:'Access bit - Page',
    0b1001:'Domain - Section', 0b1011:'Domain - Page', 0b1101:'Permission - Section', 0b1111:'Permission - Page',
    0b1000:'Precise External Abort', 0b10110:'Imprecise External Abort', 0b10:'Debug event'
}

def main(args=None):
    parser = argparse.ArgumentParser(description="Parse Luma3DS exception dumps")
    parser.add_argument("filename")
    args = parser.parse_args()
    data = b""
    with open(args.filename, "rb") as f: data = f.read()
    if unpack_from("<2I", data) != (0xdeadc0de, 0xdeadcafe):
        raise SystemExit("Invalid file format")

    version, processor, exceptionType, _, nbRegisters, codeDumpSize, stackDumpSize, additionalDataSize = unpack_from("<8I", data, 8)
    nbRegisters //= 4

    if version < (1 << 16) | 2:
        raise SystemExit("Incompatible format version, please use the appropriate parser.")

    registers = unpack_from("<{0}I".format(nbRegisters), data, 40)
    codeOffset = 40 + 4 * nbRegisters
    codeDump = data[codeOffset : codeOffset + codeDumpSize]
    stackOffset = codeOffset + codeDumpSize
    stackDump = data[stackOffset : stackOffset + stackDumpSize]
    addtionalDataOffset = stackOffset + stackDumpSize
    additionalData = data[addtionalDataOffset : addtionalDataOffset + additionalDataSize]

    if processor == 9: print("Processor: Arm9")
    else: print("Processor: Arm11 (core {0})".format(processor >> 16))

    typeDetailsStr = ""
    if exceptionType == 2:
        if (registers[16] & 0x20) == 0 and codeDumpSize >= 4:
            instr = unpack_from("<I", codeDump[-4:])[0]
            if instr == 0xe12fff7e:
                typeDetailsStr = " (kernel panic)"
            elif instr == 0xef00003c:
                typeDetailsStr = " " + (svcBreakReasons[registers[0]] if registers[0] < 3 else "(svcBreak)")
        elif (registers[16] & 0x20) == 1 and codeDumpSize >= 2:
            instr = unpack_from("<I", codeDump[-4:])[0]
            if instr == 0xdf3c:
                typeDetailsStr = " " + (svcBreakReasons[registers[0]] if registers[0] < 3 else "(svcBreak)")

    elif processor != 9 and (registers[20] & 0x80000000) != 0:
        typeDetailsStr = " (VFP exception)"

    print("Exception type: {0}{1}".format("unknown" if exceptionType >= len(handledExceptionNames) else handledExceptionNames[exceptionType], typeDetailsStr))

    if processor == 11 and exceptionType >= 2:
        xfsr = registers[18] if exceptionType == 2 else registers[17]
        print("Fault status: " + faultStatusSources[xfsr & 0xf])

    if additionalDataSize != 0:
        if processor == 11:
            print("Current process: {0} ({1:016x})".format(additionalData[:8].decode("ascii"), unpack_from("<Q", additionalData, 8)[0]))
        else:
            outName = os.path.splitext(args.filename)[0] + "_arm9mem.bin"
            with open(outName, "wb+") as f:
                f.write(additionalData)

            # We don't care if we fail, I guess
            print("Arm9 RAM dumped to {0}, size {1:x}".format(outName, additionalDataSize))

    print("\nRegister dump:\n")
    for i in range(0, nbRegisters - (nbRegisters % 2), 2):
        if i == 16: print("")
        print(makeRegisterLine(registerNames[i], registers[i], registerNames[i+1], registers[i+1]))
    if nbRegisters % 2 == 1: print("{0:<15}{1:<20}".format(registerNames[nbRegisters - 1], "{0:08x}".format(registers[nbRegisters - 1])))

    if processor == 11 and exceptionType == 3:
        print("{0:<15}{1:<20}Access type: {2}".format("FAR", "{0:08x}".format(registers[19]), "Write" if registers[17] & (1 << 11) != 0 else "Read"))

    thumb = registers[16] & 0x20 != 0
    addr = registers[15] - codeDumpSize + (2 if thumb else 4)

    print("\nCode dump:\n")

    objdump_res = ""
    try:
        path = os.path.join(os.environ["DEVKITARM"], "bin", "arm-none-eabi-objdump")

        if os.name == "nt" and path[0] == '/':
            path = ''.join((path[1], ':', path[2:]))

        objdump_res = subprocess.check_output((
                                                    path, "-marm", "-b", "binary",
                                                     "--adjust-vma="+hex(addr - codeOffset), "--start-address="+hex(addr),
                                                     "--stop-address="+hex(addr + codeDumpSize), "-D", "-z", "-M",
                                                     "reg-names-std" + (",force-thumb" if thumb else ""), args.filename
                                             )).decode("utf-8")
        objdump_res = '\n'.join(objdump_res[objdump_res.find('<.data+'):].split('\n')[1:])
    except: objdump_res = ""

    print(objdump_res if objdump_res != "" else hexdump(addr, codeDump))

    print("\nStack dump:\n")
    print(hexdump(registers[13], stackDump))

if __name__ == "__main__":
    main()
