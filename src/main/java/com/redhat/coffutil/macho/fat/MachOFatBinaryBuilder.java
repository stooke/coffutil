package com.redhat.coffutil.macho.fat;

import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.ExeFileBuilder;
import com.redhat.coffutil.pecoff.Util;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

public class MachOFatBinaryBuilder implements ExeFileBuilder {
    @Override
    public ExeFile build(File file) throws IOException {
        ByteBuffer in = Util.readFile(file);
        in.order(ByteOrder.BIG_ENDIAN);
        int magic = in.getInt();
        assert magic == MachOFatBinary.FAT_MAGIC;
        int numArch = in.getInt();
        MachOFatBinary fatfile = new MachOFatBinary();
        fatfile.setHeaders(new ArrayList<>(numArch));
        for (int i=0; i<numArch; i++) {
            int cputype = in.getInt();
            int cpuSubtype = in.getInt();
            long offset = in.getInt();
            long size = in.get();
            long align = in.get();
            MachOFatBinary.FatArch arch = new MachOFatBinary.FatArch(cputype, cpuSubtype, offset, size, align);
            fatfile.getHeaders().add(arch);
        }
        return null;
    }

    static boolean isAFatFile(File file, ByteBuffer in) {
        in.order(ByteOrder.BIG_ENDIAN);
        int magic = in.getInt(0);
        return magic == MachOFatBinary.FAT_MAGIC;
    }
}
