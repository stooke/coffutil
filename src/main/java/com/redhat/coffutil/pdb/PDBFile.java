package com.redhat.coffutil.pdb;

import com.redhat.coffutil.msf.MultiStreamFile;
import com.redhat.coffutil.coff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;

public class PDBFile extends MultiStreamFile {

    private static final int PDB_HEADERS_STREAM = 1;
    private static final int TYPE_INFO_STREAM = 2;

    private static final int VERSION_VC70 = 20000404;

    private ByteBuffer pdbHeaderStream;
    private ByteBuffer typeInfoStream;

    public void build(ByteBuffer in) {
        super.build(in);

        pdbHeaderStream = getStream(PDB_HEADERS_STREAM);
        typeInfoStream = getStream(TYPE_INFO_STREAM);
        buildPDBInfoStram(getStream(2));
    }

    void buildPDBInfoStram(ByteBuffer in) {
        int version = in.getInt();
        int signature = in.get();
        int age = in.get();
        byte[] checksum = new byte[16];
        in.get(checksum);
        System.out.format("pdbinfo: version=%d sig=%d age=%d checksum=", version, signature, age);
        Util.dumpHex(System.out, checksum);
        System.out.println();
        assert version == VERSION_VC70;  // this is the only version we can handle
    }
}
