package com.redhat.coffutil.pdb;

import com.redhat.coffutil.coff.Util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PDBBuilder {

    public PDBFile build(String fn) {
        ByteBuffer in = Util.readFile(fn);
        in.order(ByteOrder.LITTLE_ENDIAN);
        PDBFile pdbfile = new PDBFile();
        pdbfile.build(in);
        return pdbfile;
    }
}
