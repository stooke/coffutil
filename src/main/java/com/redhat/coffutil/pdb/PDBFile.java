package com.redhat.coffutil.pdb;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.cv.CVTypeSection;
import com.redhat.coffutil.cv.CVTypeSectionBuilder;
import com.redhat.coffutil.msf.MultiStreamFile;
import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.pecoff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.time.Instant;

/*
 https://llvm.org/docs/PDB/index.html
 https://github.com/jcdickinson/symblr/tree/master/Symblr.Core/Symbols/Pdb70
 http://moyix.blogspot.com/2007/08/pdb-stream-decomposition.html
 http://moyix.blogspot.com/2007/10/types-stream.html
*/

public class PDBFile extends MultiStreamFile implements ExeFile {

    private static final int PDB_HEADERS_STREAM = 2;
    private static final int TYPE_INFO_STREAM = 3;
    private static final int ID_STREAM = 5;

    /*
    private static final int NAME_MAP_STREAM = 3;
    private static final int MODULE_INFO_STREAM = 4;
    private static final int GLOBAL_INFO_STREAM = 5;
    private static final int PUBLIC_INFO_STREAM = 6;
    private static final int TYPE_HASH_STREAM = 7;
    */
    private static final int VERSION_VC70 = 20000404;

    private StreamDef pdbHeaderStream;
    private StreamDef typeInfoStream;
    private StreamDef idStream;

    private CVTypeSection typeSection;
    private CVTypeSection idSection;

    /* PDB header */
    private int version = 0;
    private int signature = 0;
    private int age = 0;
    private byte[] checksum = null;
    private Instant sig = null;

    public void build(ByteBuffer in) {
        super.build(in);

        pdbHeaderStream = getStream(PDB_HEADERS_STREAM);
        buildPDBHeader(pdbHeaderStream);

        typeInfoStream = getStream(TYPE_INFO_STREAM);
        typeSection = buildTypeInfo(typeInfoStream);

        idStream = getStream(ID_STREAM);
        idSection = buildTypeInfo(idStream);

        for (int i = 4; i < streamCount(); i++) {
            processUnknownStream(getStream(i));
        }
    }

    private void processUnknownStream(@SuppressWarnings("unused") StreamDef stream) {
        /*
        if (stream.length() < 4) {
            return;
        }
        ByteBuffer in = stream.get();
        int cvsig = in.getInt();
        if (cvsig == CV_SIGNATURE_C13) {
            //new CVSymbolSectionBuilder().parseCVSymbolSubsection(in, 0, stream.length());
            //ss.dump(System.out);
        }

         */
    }

    public void dump(PrintStream out) {
        CoffUtilContext ctx = CoffUtilContext.getInstance();

        if (ctx.getDebugLevel() > 1) {
            super.dump(out);
        }

        out.println("pdbHeaderStream: " + pdbHeaderStream.toString());
        out.format("pdbinfo: version=%d sig=%d(%s) age=%d len=%d checksum=[%s]\n", version, signature, sig.toString(), age, pdbHeaderStream.length(), Util.dumpHex(checksum));
        if (ctx.getDumpHex()) {
            pdbHeaderStream.dumpData(out);
        }

        out.println("typeInfoStream: " + typeInfoStream.toString());
        if (ctx.dumpTypes()) {
            typeSection.dump(out);
        }
        if (ctx.getDumpHex()) {
            typeInfoStream.dumpData(out);
        }

        out.println("idStream: " + idStream.toString());
        if (ctx.dumpTypes()) {
            idSection.dump(out);
        }
        if (ctx.getDumpHex()) {
            idStream.dumpData(out);
        }

        dumpStream(ctx, out, 4);
        for (int i = 6; i < streamCount(); i++) {
            dumpStream(ctx, out, i);
        }
    }

    private void dumpStream(CoffUtilContext ctx, PrintStream out, int i) {
        StreamDef s = getStream(i);
        out.println("stream " + i + ": " + s.toString());
        if (ctx.getDumpHex()) {
            s.dumpData(out);
        }
    }

    private CVTypeSection buildTypeInfo(StreamDef stream) {
        final int typeInfoBegin = 0x38; /* derived by inspection and probably inaccurate */
        return new CVTypeSectionBuilder().build(stream.get(), typeInfoBegin, stream.length());
    }

    private void buildPDBHeader(StreamDef stream) {
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
        int hsize = in.getShort();
      //  int hflag = in.getShort();
        int htop = in.position() + hsize;
     //   int nameCount = 0;
        while (in.position() < htop) {
            String name = Util.getString0(in, htop - in.position());
            System.out.format("name: %s\n", name);
     //       nameCount++;
        }
        // pad to even
        while (in.position() % 2 != 0) {
            in.get();
        }
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
