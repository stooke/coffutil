package com.redhat.coffutil.pdb;

import com.redhat.coffutil.msf.MultiStreamFile;
import com.redhat.coffutil.pecoff.Util;

import java.nio.ByteBuffer;
import java.time.Instant;

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

        // read header
        int version = in.getInt();
        int signature = in.getInt();
        int age = in.getInt();
        byte[] checksum = new byte[16];
        in.get(checksum);
        Instant sig = Instant.ofEpochSecond(signature);
        System.out.format("pdbinfo: version=%d sig=%d(%s) age=%d checksum=[", version, signature, sig.toString(), age);
        Util.dumpHex(System.out, checksum);
        System.out.println("]");
        assert version == VERSION_VC70;  // this is the only version we can handle

        // read hash table
    }
}
