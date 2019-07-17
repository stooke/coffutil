package com.redhat.coffutil;


import java.io.PrintStream;
import java.nio.ByteBuffer;

class PEHeader {

    /**
     // from https://wiki.osdev.org/PE
     // 1 byte aligned
     struct PeHeader {
     uint32_t mMagic; // PE\0\0 or 0x00004550
     uint16_t mMachine;
     uint16_t mNumberOfSections;
     uint32_t mTimeDateStamp;
     uint32_t mPointerToSymbolTable;
     uint32_t mNumberOfSymbols;
     uint16_t mSizeOfOptionalHeader;
     uint16_t mCharacteristics;
     };
     **/

    private final int pemagic;
    private final int pemachine;
    final int numsections;
    private final int timeDateStamp;
    final int symPtr;
    final int numSymbols;
    final int optionalHeaderSize;
    private final int characteristics;

    PEHeader(ByteBuffer in) {
        int offset = in.position();
        pemagic = in.getShort();
        final boolean isPE = (pemagic == 0x4550);
        if (isPE) {
            // magic is 4 bytes in a PE executable
            in.getShort();
        }
        pemachine = isPE ? in.getShort() : 0; // 0x8664
        numsections = in.getShort();
        timeDateStamp = in.getInt();
        symPtr = in.getInt();
        numSymbols = in.getInt();
        optionalHeaderSize = in.getShort();
        characteristics = in.getShort();
    }

    String validate() {
        if (pemagic != 0x4550) {  // 0x4550
            return("invalid PE magic: " + pemagic);
        }
        if (pemachine != 0x8664) {
            return("invalid machine: " + pemachine);
        }
        return null;
    }

    void dump(PrintStream out) {
        System.err.println("magic = " + pemagic + " machine = " + pemachine + " nsections = " + numsections + " nsymbols = " + numSymbols);
        if ((characteristics & 0x2) == 0x2) {
            out.println("   executable image");
        }
        if ((characteristics & 0x20) == 0x20) {
            out.println("   large addess aware");
        }
    }
}

