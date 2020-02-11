package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class CoffRelocationTable {

    static class Entry {
        private int virtualAddr;
        private int symbolIndex;
        private int type;

        Entry(int addr, int symbolIndex, int type) {
            this.symbolIndex = symbolIndex;
            this.virtualAddr = addr;
            this.type = type;
        }

        void dump(PrintStream out, CoffFile ofile) {
            PESymbol symbol = ofile.getSymbols().get(symbolIndex);
            final String descr;
            /* assume x64 */
            switch (type) {
                case 0x00: descr = "Ignore(0)"; break;
                case 0x01: descr = "IMAGE_REL_AMD64_ADDR64(1)"; break;
                case 0x03: descr = "IMAGE_REL_AMD64_ADDR32NB(3)"; break;
                case 0x04: descr = "IMAGE_REL_AMD64_REL32(4)"; break;
                case 0x06: descr = "IMAGE_REL_AMD64_REL32_2(6)"; break;
                case 0x0a: descr = "IMAGE_REL_AMD64_SECTION(0x0a)"; break;
                case 0x0b: descr = "IMAGE_REL_AMD64_SECREL(0x0b)"; break;
                case 0x14: descr = "IMAGE_REL_I386_REL32(0x0b)"; break;
                default: descr = "Unknown(" + type + ")"; break;
            }
            if (symbol != null) {
                String sym = symbol.getName();
                out.format("  reloc addr=0x%06x type=%-2d sym=%-10s %s\n", virtualAddr, type, sym, descr);
            } else {
                out.format("  reloc addr=0x%06x type=%-2d *** unknown index=%d\n", virtualAddr, type, symbolIndex);
            }
        }
    }

    CoffRelocationTable.Entry[] relocs;

    CoffRelocationTable(ByteBuffer in, PESection section, PEFileHeader hdr) {
        int offset = section.getRelocationPtr();
        int nLines = section.getRelocationCount();
        relocs = read(in, offset, nLines);
    }

    private CoffRelocationTable.Entry[] read(ByteBuffer in, int offset, int nLines) {
        if (nLines == 0) {
            return null;
        }
        in.position(offset);
        CoffRelocationTable.Entry[] ln = new CoffRelocationTable.Entry[nLines];
        for (int i=0; i < nLines; i++) {
            int addr = in.getInt();
            int symIdx = in.getInt();
            int type = in.getShort();
            CoffRelocationTable.Entry e = new CoffRelocationTable.Entry(addr, symIdx, type); // symtab index or pysical addr
            ln[i] = e;
        }
        return ln;
    }

    void dump(PrintStream out, CoffFile ofile) {
        if (relocs != null) {
            int limit = 50;
            for (CoffRelocationTable.Entry e : relocs) {
                e.dump(out, ofile);
                if (limit-- < 0) break;
            }
        }
    }

}

