package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.CoffUtilContext;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PESection {

    private static final int COFF_SECTION_HEADER_SIZE = 40;

    private static final int COFF_TEXT_SECTION  = 0x00000020;   /* .text IMAGE_SCN_CNT_CODE */
    private static final int COFF_DATA_SECTION  = 0x00000040;   /* .data IMAGE_SCN_CNT_INITIALIZED_DATA */
    private static final int COFF_BSS_SECTION   = 0x00000080;   /* .bss  IMAGE_SCN_CNT_UNINITIALIZED_DATA */

    private static final int PE_OTHER_SECTION = 0x00000100;     /* IMAGE_SCN_LNK_OTHER */
    private static final int PE_INFO_SECTION  = 0x00000200;     /* IMAGE_SCN_LNK_INFO */
    private static final int PE_REMOVE        = 0x00000800;     /* IMAGE_SCN_LNK_REMOVE */
    private static final int PE_COMDAT        = 0x00001000;     /* IMAGE_SCN_LNK_COMDAT */

    private static final int PE_ALIGNMENT_MASK = 0x00f00000;
    private static final int PE_ALIGNMENT_SHIFT = 20;

    private static final int PE_EXTENDED_RELOCS  = 0x01000000; /* IMAGE_SCN_LNK_NRELOC_OVFL */
    private static final int PE_DISARDABLE       = 0x02000000; /* IMAGE_SCN_MEM_DISCARDABLE */
    private static final int PE_DONT_CACHE       = 0x04000000; /* IMAGE_SCN_MEM_NOT_CACHED */
    private static final int PE_DONT_PAGE        = 0x08000000; /* IMAGE_SCN_MEM_NOT_PAGED */
    private static final int PE_SHAREABLE        = 0x10000000; /* IMAGE_SCN_MEM_SHARED */
    private static final int PE_PERM_EXECUTE     = 0x20000000; /* IMAGE_SCN_MEM_EXECUTE */
    private static final int PE_PERM_READ        = 0x40000000; /* IMAGE_SCN_MEM_READ */
    private static final int PE_PERM_WRITE       = 0x80000000; /* IMAGE_SCN_MEM_WRITE */

    private PESectionHeader sectionHeader;
    private ByteBuffer rawData;
    private CoffLineNumberTable lineNumberTable;
    private CoffRelocationTable relocations;

    private PESection() {
    }

    public static PESection build(ByteBuffer in, PEFileHeader hdr) {
        PESection section = new PESection();
        PESectionHeader sectionHeader = PESectionHeader.build(in, hdr);
        section.sectionHeader = sectionHeader;
        int oldPos = in.position();
        if (in.hasArray() && in.array().length > 0) {
            in.position(sectionHeader.rawDataPtr);
            section.rawData = in.slice().asReadOnlyBuffer();
            section.rawData.order(ByteOrder.LITTLE_ENDIAN);
        }
        section.loadLineNumbersAndRelocations(in, hdr);
        in.position(oldPos);
        return section;
    }

    private void loadLineNumbersAndRelocations(ByteBuffer in, PEFileHeader hdr) {
        lineNumberTable = new CoffLineNumberTable(in, this, hdr);
        relocations = new CoffRelocationTable(in, this, hdr);
    }

    String validate() {
        return null;
    }

    public int alignment() {
        int align = (getCharacteristics() & PE_ALIGNMENT_MASK) >> PE_ALIGNMENT_SHIFT;
        return 1 << (align-1);
    }

    public CoffRelocationTable getRelocations() {
        return relocations;
    }

    public PESectionHeader getSectionHeader() {
        return sectionHeader;
    }

    void dump(PrintStream out, CoffFile objectFile) {
        String bName = (getName() + "          ").substring(0, PEStringTable.SHORT_LENGTH);
        out.format("section: %8s flags=[%s]", getName(), translateCharacteristics(getCharacteristics()));
        if (getVirtualSize() != 0) {
            out.format(" vaddr=0x%x,vsize=0x%x", getVirtualAddress(), getVirtualSize());
        }
        if (getRawDataSize() != 0) {
            out.format(" rawPtr=0x%x,rawSize=0x%x", getRawDataPtr(), getRawDataSize());
        }
        if (getLineNumberCount() != 0) {
            out.format(" linePtr=0x%x,lineSize=0x%x", getLineNumberPtr(), getLineNumberCount());
        }
        if (getRelocationCount() != 0) {
            out.format(" relocPtr=0x%x,relocSize=0x%x", getRelocationPtr(), getRelocationCount());
        }
        if (CoffUtilContext.getInstance().dumpLinenumbers() && getLineNumberCount() != 0) {
            out.println();
            lineNumberTable.dump(out, Integer.MAX_VALUE);
        }
        if (CoffUtilContext.getInstance().dumpRelocations() && getRelocationCount() != 0) {
            out.println();
            relocations.dump(out, objectFile, Integer.MAX_VALUE);
        }
        out.println();
    }

    public String getName() {
        return sectionHeader.name;
    }

    int getVirtualSize() {
        return sectionHeader.virtualSize;
    }

    int getVirtualAddress() {
        return sectionHeader.virtualAddress;
    }

    public int getRawDataSize() {
        return sectionHeader.rawDataSize;
    }

    public int getRawDataPtr() {
        return sectionHeader.rawDataPtr;
    }

    int getRelocationPtr() {
        return sectionHeader.relocationPtr;
    }

    int getLineNumberPtr() {
        return sectionHeader.lineNumberPtr;
    }

    int getRelocationCount() {
        return sectionHeader.relocationCount;
    }

    int getLineNumberCount() {
        return sectionHeader.lineNumberCount;
    }

    public int getCharacteristics() {
        return sectionHeader.characteristics;
    }

    CoffLineNumberTable getLineNumberTable() {
        return lineNumberTable;
    }

    public String translateCharacteristics(int c) {
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
        int align = (c & PE_ALIGNMENT_MASK) >> PE_ALIGNMENT_SHIFT;
        sb.append(" align=").append(align);
        c = c & ~PE_ALIGNMENT_MASK;
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

    public static class PESectionHeader {

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

        private ByteBuffer rawHeaderData;

        private void buildHeader(ByteBuffer in, PEFileHeader fileHeader) {

            //int offset = in.position();
            if (in.hasArray()) {
                rawHeaderData = in.slice().asReadOnlyBuffer();
                rawHeaderData.order(ByteOrder.LITTLE_ENDIAN);
            } else {
                CoffUtilContext.getInstance().fatal("**** no backing array ****");
            }
            name = PEStringTable.resolve(in, fileHeader);
            virtualSize = in.getInt();
            virtualAddress = in.getInt();
            rawDataSize = in.getInt();
            rawDataPtr = in.getInt();
            relocationPtr = in.getInt();
            lineNumberPtr = in.getInt();
            relocationCount = 0xffff & (int)in.getShort();
            lineNumberCount = 0xffff & (int)in.getShort();
            characteristics = in.getInt();
        }

        static PESectionHeader build(ByteBuffer in, PEFileHeader fileHeader) {
            PESectionHeader hdr = new PESectionHeader();
            hdr.buildHeader(in, fileHeader);
            return hdr;
        }
    }
}
