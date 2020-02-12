package com.redhat.coffutil.pdb;

import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.ExeFileBuilder;
import com.redhat.coffutil.pecoff.Util;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PDBBuilder implements ExeFileBuilder {

    public ExeFile build(File file) throws IOException {
        return buildPDBFile(file);
    }

    public PDBFile buildPDBFile(File file) throws IOException {
        ByteBuffer in = Util.readFile(file);
        in.order(ByteOrder.LITTLE_ENDIAN);
        PDBFile pdbfile = new PDBFile();
        pdbfile.build(in);
        return pdbfile;
    }
}
