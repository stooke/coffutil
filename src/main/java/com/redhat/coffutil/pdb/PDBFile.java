package com.redhat.coffutil.pdb;

import com.redhat.coffutil.msf.MultiStreamFile;
import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.pecoff.Util;

import java.nio.ByteBuffer;
import java.time.Instant;

public class PDBFile extends MultiStreamFile implements ExeFile {

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

    private void buildPDBInfoStram(ByteBuffer in) {

        /* read header */
        int version = in.getInt();
        int signature = in.getInt();
        int age = in.getInt();
        byte[] checksum = new byte[16];
        in.get(checksum);
        Instant sig = Instant.ofEpochSecond(signature);
        CoffUtilContext.getInstance().info("pdbinfo: version=%d sig=%d(%s) age=%d checksum=[%s]\n", version, signature, sig.toString(), age, Util.dumpHex(checksum));
        assert version == VERSION_VC70;  /* this is the only version we can handle */
        // TODO read hash table
    }
}
