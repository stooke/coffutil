package com.redhat.coffutil.coff;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class PDBBuilder {

    PDBFile build(String fn) {
        ByteBuffer in = Util.readFile(fn);
        in.order(ByteOrder.LITTLE_ENDIAN);
        PDBFile pdbfile = new PDBFile();
        pdbfile.build(in);
        return pdbfile;
    }
}
