package com.redhat.coffutil.pdb;

import com.redhat.coffutil.pecoff.Util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PDBBuilder {

    public PDBFile build(String fn) throws IOException {
        ByteBuffer in = Util.readFile(fn);
        in.order(ByteOrder.LITTLE_ENDIAN);
        PDBFile pdbfile = new PDBFile();
        pdbfile.build(in);
        return pdbfile;
    }
}
