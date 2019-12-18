package com.redhat.coffutil.coff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class PESectionHeader {

    private static final int COFF_SECTION_HEADER_SIZE = 40;

    private static final int COFF_TEXT_SECTION  = 0x00000020;   // .text IMAGE_SCN_CNT_CODE
    private static final int COFF_DATA_SECTION  = 0x00000040;   // .data IMAGE_SCN_CNT_INITIALIZED_DATA
    private static final int COFF_BSS_SECTION   = 0x00000080;   // .bss  IMAGE_SCN_CNT_UNINITIALIZED_DATA

    private static final int PE_OTHER_SECTION = 0x00000100;     // IMAGE_SCN_LNK_OTHER
    private static final int PE_INFO_SECTION  = 0x00000200;     // IMAGE_SCN_LNK_INFO
    private static final int PE_REMOVE        = 0x00000800;     // IMAGE_SCN_LNK_REMOVE
    private static final int PE_COMDAT        = 0x00001000;     // IMAGE_SCN_LNK_COMDAT

    private static final int PE_ALINGMENT_MASK   = 0x00f00000;
    private static final int PE_ALINGMENT_SHIFT  = 20;

    private static final int PE_EXTENDED_RELOCS  = 0x01000000; // IMAGE_SCN_LNK_NRELOC_OVFL
    private static final int PE_DISARDABLE       = 0x02000000; // IMAGE_SCN_MEM_DISCARDABLE
    private static final int PE_DONT_CACHE       = 0x04000000; // IMAGE_SCN_MEM_NOT_CACHED
    private static final int PE_DONT_PAGE        = 0x08000000; // IMAGE_SCN_MEM_NOT_PAGED
    private static final int PE_SHAREABLE        = 0x10000000; // IMAGE_SCN_MEM_SHARED
    private static final int PE_PERM_EXECUTE     = 0x20000000; // IMAGE_SCN_MEM_EXECUTE
    private static final int PE_PERM_READ        = 0x40000000; // IMAGE_SCN_MEM_READ
    private static final int PE_PERM_WRITE       = 0x80000000; // IMAGE_SCN_MEM_WRITE

    private String name;
    private int virtualSize;
    private int virtualAddress;
    private int rawDataSize;
    private int rawDataPtr;
    private int relocationPtr;
    private int lineNumberPtr;
    private int relocationCount;
    private int lineNumberCount;
    private int characteristics;

    private CoffLineNumberTable lineNumberTable;
    private CoffRelocationTable relocations;

    private ByteBuffer rawHeaderData;
    private ByteBuffer rawData;

    private PESectionHeader() {
    }

    static PESectionHeader build(ByteBuffer in, PEHeader hdr) {
        PESectionHeader sectionHeader = new PESectionHeader();
        sectionHeader._build(in, hdr);
        int oldPos = in.position();
        sectionHeader.loadLineNumbersAndRelocations(in, hdr);
        in.position(oldPos);
        return sectionHeader;
    }

    private void _build(ByteBuffer in, PEHeader hdr) {

        //int offset = in.position();
        if (in.hasArray()) {
            rawHeaderData = ByteBuffer.wrap(in.array(), in.position(), COFF_SECTION_HEADER_SIZE);
        } else {
            System.err.println("**** no backing array ****");
        }
        name = PEStringTable.resolve(in, hdr);
        virtualSize = in.getInt();
        virtualAddress = in.getInt();
        rawDataSize = in.getInt();
        rawDataPtr = in.getInt();
        relocationPtr = in.getInt();
        lineNumberPtr = in.getInt();
        relocationCount = in.getShort();
        lineNumberCount = in.getShort();
        characteristics = in.getInt();
        if (in.hasArray() && in.array().length > 0) {
            rawData = ByteBuffer.wrap(in.array(), rawDataPtr, rawDataSize);
        }
    }

    private void loadLineNumbersAndRelocations(ByteBuffer in, PEHeader hdr) {
        lineNumberTable = new CoffLineNumberTable(in, this, hdr);
        relocations = new CoffRelocationTable(in, this, hdr);
    }

    String validate() {
        return null;
    }

    void dump(PrintStream out, PECoffObjectFile objectifle) {
        String bName = (getName() + "          ").substring(0, PEStringTable.SHORT_LENGTH);
        out.print("section: " + bName + " flags=[" + translateCharacteristics(getCharacteristics()) + "]");
        if (getVirtualSize() != 0) {
            out.printf(" vaddr=0x%x,vsize=0x%x", getVirtualAddress(), getVirtualSize());
        }
        if (getRawDataSize() != 0) {
            out.printf(" rawPtr=0x%x,rawSize=0x%x", getRawDataPtr(), getRawDataSize());
        }
        if (getLineNumberCount() != 0) {
            out.printf(" linePtr=0x%x,lineSize=0x%x", getLineNumberPtr(), getLineNumberCount());
            lineNumberTable.dump(out);
        }
        if (getRelocationCount() != 0) {
            out.printf(" relocPtr=0x%x,relocSize=0x%x", getRelocationPtr(), getRelocationCount());
            //relocations.dump(out, objectifle);
        }
        out.println();
    }

    /**
     // from https://wiki.osdev.org/PE
     struct IMAGE_SECTION_HEADER { // size 40 bytes
     char[8]  name;
     uint32_t virtualSize;
     uint32_t virtualAddress;
     uint32_t rawDataSize;
     uint32_t rawDataPtr;
     uint32_t relocationPtr;
     uint32_t lineNumberPtr;
     uint16_t mNumberOfRealocations;
     uint16_t lineNumberCount;
     uint32_t characteristics;
     };
     ***/
    String getName() {
        return name;
    }

    int getVirtualSize() {
        return virtualSize;
    }

    int getVirtualAddress() {
        return virtualAddress;
    }

    int getRawDataSize() {
        return rawDataSize;
    }

    int getRawDataPtr() {
        return rawDataPtr;
    }

    int getRelocationPtr() {
        return relocationPtr;
    }

    int getLineNumberPtr() {
        return lineNumberPtr;
    }

    int getRelocationCount() {
        return relocationCount;
    }

    int getLineNumberCount() {
        return lineNumberCount;
    }

    int getCharacteristics() {
        return characteristics;
    }

    CoffLineNumberTable getLineNumberTable() {
        return lineNumberTable;
    }

    private String translateCharacteristics(int c) {
        StringBuffer sb = new StringBuffer(200);

        c = testCharacteristic(c, sb, COFF_TEXT_SECTION, "text");
        c = testCharacteristic(c, sb, COFF_DATA_SECTION, "data");
        c = testCharacteristic(c, sb, COFF_BSS_SECTION, "bss");
        c = testCharacteristic(c, sb, PE_OTHER_SECTION, "(other)");
        c = testCharacteristic(c, sb, PE_INFO_SECTION, "info");
        c = testCharacteristic(c, sb, PE_REMOVE, "remove");
        c = testCharacteristic(c, sb, PE_COMDAT, "comdat");
        c = testCharacteristic(c, sb, PE_EXTENDED_RELOCS, "exetended relocs");
        c = testCharacteristic(c, sb, PE_DISARDABLE, "disardable");
        c = testCharacteristic(c, sb, PE_DONT_CACHE, "nocache");
        c = testCharacteristic(c, sb, PE_DONT_PAGE, "nopage");
        c = testCharacteristic(c, sb, PE_SHAREABLE, "shareable");
        c = testCharacteristic(c, sb, PE_PERM_EXECUTE, "execute");
        c = testCharacteristic(c, sb, PE_PERM_READ, "read");
        c = testCharacteristic(c, sb, PE_PERM_WRITE, "write");
        int align = (c & PE_ALINGMENT_MASK) >> PE_ALINGMENT_SHIFT;
        sb.append(" align=").append( 1 << (align-1) );
        c = c & ~PE_ALINGMENT_MASK;
        if (c != 0) {
            sb.append(" (remaining bits: ").append(c).append(")");
        }
        return sb.toString();
    }

    private int testCharacteristic(int c, StringBuffer sb, int mask, String msg) {
        if ((c & mask) == mask) {
            c = c & ~mask;
            if (sb.length() > 0) {
                sb.append(" ");
            }
            sb.append(msg);
        }
        return c;
    }

}