package com.redhat.coffutil.pdb;

import com.redhat.coffutil.cv.CVTypeSection;
import com.redhat.coffutil.cv.CVTypeSectionBuilder;
import com.redhat.coffutil.msf.MultiStreamFile;
import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.pecoff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.time.Instant;

// https://llvm.org/docs/PDB/index.html
// https://github.com/jcdickinson/symblr/tree/master/Symblr.Core/Symbols/Pdb70
// http://moyix.blogspot.com/2007/08/pdb-stream-decomposition.html
// http://moyix.blogspot.com/2007/10/types-stream.html

public class PDBFile extends MultiStreamFile implements ExeFile {

    private static final int PDB_HEADERS_STREAM = 2;
    private static final int TYPE_INFO_STREAM = 3;

    private static final int VERSION_VC70 = 20000404;

    private StreamDef pdbHeaderStream;
    private StreamDef typeInfoStream;

    /* PDB info */
    private int version = 0;
    private int signature = 0;
    private int age = 0;
    private byte[] checksum = null;
    private Instant sig = null;

    public void build(ByteBuffer in) {
        super.build(in);

        pdbHeaderStream = getStream(PDB_HEADERS_STREAM);
        buildPDBInfo(pdbHeaderStream);
        typeInfoStream = getStream(TYPE_INFO_STREAM);
        buildTypeInfo(typeInfoStream);
    }

    public void dump(PrintStream out) {
        super.dump(out);

        out.println("pdbHeaderStream: " + pdbHeaderStream.toString());
        pdbHeaderStream.dumpData(out);
        CoffUtilContext.getInstance().info("pdbinfo: version=%d sig=%d(%s) age=%d len=%d checksum=[%s]\n", version, signature, sig.toString(), age, pdbHeaderStream.length(), Util.dumpHex(checksum));

        out.println("typeInfoStream: " + typeInfoStream.toString());
        typeInfoStream.dumpData(out);
        CVTypeSection ts = new CVTypeSectionBuilder().build(typeInfoStream.get(), 0, typeInfoStream.length());

        for (int i = 4; i < streamCount(); i++) {
            StreamDef s = getStream(i);
            out.println("stream " + i + ": " + s.toString());
            s.dumpData(out);
        }
    }

    private void buildTypeInfo(StreamDef stream) {

    }

    private void buildPDBInfo(StreamDef stream) {
        ByteBuffer in = stream.get();

        /* read header */
        version = in.getInt();
        signature = in.getInt();
        age = in.getInt();
        checksum = new byte[16];
        in.get(checksum);
        sig = Instant.ofEpochSecond(signature);
        assert version == VERSION_VC70;  /* this is the only version we can handle */
        // TODO read hash table
    }

    /* from http://www.godevtool.com/Other/pdb.htm
    Symbol stream
    In "DS" files each symbol is in the following structure which is similar to that found in the earlier "JG" files, except that the symbol type numbers have changed and the string containing the symbol name is no longer preceded by a size byte (ie. it's no longer a pascal string):-
            +0h word - size of structure not including this word but including the padding after the string
            +2h word - type of symbol.  So far the following are known:-
                    1108h = data type (from h or inc file)
                110Ch = symbol marked as "static" in the object file
                 110Eh = global data variables, function names, imported functions, local variables
                1125h = function prototype
            +4h dword - reserved
            +8h dword - offset value
            +0Ch word - section number
            +0Eh bytes - null terminated string containing symbol name
            +?h bytes - padding to next dword
            */
}
