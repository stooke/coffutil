package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class CoffLineNumberTable {

    static class Entry {
        private final int lineNumber;
        private final int symbolIndex;
        private final int physicalAddress;

        Entry(int symbolIndex) {
            this.symbolIndex = symbolIndex;
            this.lineNumber = 0;
            this.physicalAddress = 0;
        }

        Entry(int lineNumber, int physicalAddress) {
            this.lineNumber = lineNumber;
            this.physicalAddress = physicalAddress;
            this.symbolIndex = 0;
        }

        void dump(PrintStream out) {
            if (symbolIndex != 0) {
                out.println("line number symol idx = " + symbolIndex);
            } else {
                out.println("line number " + lineNumber + " addr " + physicalAddress);
            }
        }
    }

    private final Entry[] lineNumbers;

    CoffLineNumberTable(ByteBuffer in, PESection section, PEFileHeader hdr) {
        int offset = section.getLineNumberPtr();
        int nLines = section.getLineNumberCount();
        lineNumbers = read(in, offset, nLines);
    }

    private Entry[] read(ByteBuffer in, int offset, int nLines) {
        if (nLines == 0) {
            return null;
        }
        in.position(offset);
        Entry[] ln = new Entry[nLines];
        for (int i=0; i < nLines; i++) {
            int addr = in.getInt();
            int lineNo = in.getShort();
            Entry e = lineNo == 0 ? new Entry(addr) : new Entry(lineNo, addr); // symtab index or pysical addr
            ln[i] = e;
        }
        return ln;
    }

    void dump(PrintStream out, int limit) {
        if (lineNumbers != null) {
            for (Entry e : lineNumbers) {
                e.dump(out);
                if (limit-- < 0) break;
            }
        }
    }
}
