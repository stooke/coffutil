package com.redhat.coffutil;

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

        void dump(PrintStream out, PECoffObjectFile ofile) {
            PESymbol symbol = ofile.getSymbols().get(symbolIndex);
            if (symbol != null) {
                String sym = symbol.getName();
                out.printf("  reloc addr=0x%x type=%d sym=%s\n", virtualAddr, type, sym);
            } else {
                out.printf("  reloc addr=0x%x type=%d *** unknown index=%d\n", virtualAddr, type, symbolIndex);
            }
        }
    }

    CoffRelocationTable.Entry[] relocs;

    CoffRelocationTable(ByteBuffer in, PESectionHeader section, PEHeader hdr) {
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

    void dump(PrintStream out, PECoffObjectFile ofile) {
        if (relocs != null) {
            for (CoffRelocationTable.Entry e : relocs) {
                e.dump(out, ofile);
            }
        }
    }

}

