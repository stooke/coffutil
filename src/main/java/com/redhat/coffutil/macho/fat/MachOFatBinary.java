package com.redhat.coffutil.macho.fat;

import com.redhat.coffutil.ExeFile;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class MachOFatBinary implements ExeFile {

    static final int FAT_MAGIC = 0xCAFEBABE; /* must be read in big-endian */

    private ArrayList<FatArch> headers;

    @Override
    public void dump(PrintStream out) {
        out.format("Mach-O fat binary:\n");
        for (FatArch arch : headers) {
            out.format("  %s\n", arch);
        }
    }

    ByteBuffer get(int i) {
        FatArch arch = headers.get(i);
        return null; /* TODO */
    }

    @Override
    public String toString() {
        return String.format("MachOFatBinary(n=%d)", headers.size());
    }

    public ArrayList<FatArch> getHeaders() {
        return headers;
    }

    public void setHeaders(ArrayList<FatArch> headers) {
        this.headers = headers;
    }

    static class FatArch {
        private int cpuType;
        private int cpuSubtype;
        private long offset;
        private long size;
        private long align;

        FatArch(int cputype, int cpuSubtype, long offset, long size, long align) {
            this.cpuType = cputype;
            this.cpuSubtype = cpuSubtype;
            this.offset = offset;
            this.size = size;
            this.align = align;
        }

        @Override
        public String toString() {
            return String.format("FatArch(%d.%d 0x%x 0x%x %d)", cpuType, cpuSubtype, offset, size, align);
        }
        public int getCpuType() {
            return cpuType;
        }

        public void setCpuType(int cpuType) {
            this.cpuType = cpuType;
        }

        public int getCpuSubtype() {
            return cpuSubtype;
        }

        public void setCpuSubtype(int cpuSubtype) {
            this.cpuSubtype = cpuSubtype;
        }

        public long getOffset() {
            return offset;
        }

        public void setOffset(long offset) {
            this.offset = offset;
        }

        public long getSize() {
            return size;
        }

        public void setSize(long size) {
            this.size = size;
        }

        public long getAlign() {
            return align;
        }

        public void setAlign(long align) {
            this.align = align;
        }
    }
}
