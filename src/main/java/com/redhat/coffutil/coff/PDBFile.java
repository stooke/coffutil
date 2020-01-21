package com.redhat.coffutil.coff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class PDBFile extends MultiStreamFile {

    private static final int PDB_HEADERS_STREAM = 1;
    private static final int TYPE_INFO_STREAM = 2;

    private StreamDef pdbHeaderStream;
    private StreamDef typeInfoStream;

    void build(ByteBuffer in) {
        super.build(in);

        pdbHeaderStream = streams[PDB_HEADERS_STREAM];
        pdbHeaderStream.get(in);
        typeInfoStream = streams[TYPE_INFO_STREAM];
        typeInfoStream.get(in);

        // fixup for dump()
        for (int i=0; i<Math.min(20, streams.length); i++) {
            streams[i].get(in);
        }
    }

    void dump(PrintStream out) {
        super.dump(out);
        /**
        out.println("PDB header stream:");
        pdbHeaderStream.dumpData(out);
        out.println("type info stream:");
        typeInfoStream.dumpData(out);
         **/
        for (int i=0; i<Math.min(20, streams.length); i++) {
            out.format("stream %d: ", i);
            StreamDef stream = streams[i];
            stream.dumpData(out);
        }
    }
}
