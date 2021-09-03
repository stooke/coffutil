package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class PERelocSection {

    public static class PERelocBlock {

        static final int LENGTH = 4096;
        final int addr;
        final int count;
        PERelocEntry[] entries;

        PERelocBlock(int addr, int count) {
            this.addr = addr;
            this.count = count;
            this.entries = new PERelocEntry[count];
        }
        boolean inRange(int low, int high) {
            return (low >= addr && low < (addr + LENGTH)) || (high >= addr && high < (addr + LENGTH));
        }
    }

    public static class PERelocEntry {

        int addr;
        int type;

        PERelocEntry(int addr, int type) {
            this.addr = addr;
            this.type = type;
        }

        boolean inRange(int begin, int end) {
            return begin <= addr && addr < end;
        }

        public void dump(PrintStream out) {
            out.format(" recloc 0x%6x %d\n", addr, type);
        }
    }

    private final Map<Integer, PERelocBlock> relocBlocks = new LinkedHashMap<>(100);

    PERelocSection(ByteBuffer in, PESection section, PEFileHeader hdr) {
        final int sectionBegin = section.getRawDataPtr();
        final int sectionEnd = sectionBegin + section.getRawDataSize();
        final int imageBase = 0;
        in.position(sectionBegin);
        while (in.position() < sectionEnd) {
            int va = imageBase + in.getInt();
            int bs = in.getInt();
            if (bs == 0) {
                break;
            }
            /* 'bs' includes size of header (vs, bs; 4 bytes each) and each entry is two bytes. */
            int count = (bs - 8) / 2;
            PERelocBlock block = new PERelocBlock(va, count);
            for (int i = 0; i < count; i++) {
                int e = in.getShort();
                int entryAddr = va + (e & 0xfff);
                int entryType = (e >> 12) & 0xf;
                block.entries[i] = new PERelocEntry(entryAddr, entryType);
            }
            relocBlocks.put(va, block);
        }
    }

    public List<PERelocEntry> inRange(int begin, int end) {
        return relocBlocks.values().stream().filter(f -> f.inRange(begin, end)).flatMap(f -> Arrays.stream(f.entries)).filter(e -> e.inRange(begin, end)).collect(Collectors.toList());
    }

    void dump(PrintStream out, int limit) {
        int count = 0;
        int blockIdx = 0;
        for (PERelocBlock block : relocBlocks.values()) {
            for (PERelocEntry entry : block.entries) {
                if (count > limit) {
                    return;
                }
                out.format(" recloc 0x%03x 0x%6x %d\n", blockIdx, entry.addr, entry.type);
                count++;
            }
            blockIdx++;
        }
    }
}
