package com.redhat.coffutil.pecoff;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class CoffObjectFileBuilder {

    PrintStream out = System.out;

    CoffObjectFile build(String fn) throws IOException {
        ByteBuffer in = Util.readFile(fn);
        return build(in);
    }

    private CoffObjectFile build(ByteBuffer in) {
        final CoffObjectFile coffFile;
        in.order(ByteOrder.LITTLE_ENDIAN);
        in.rewind();
        // test if this is an executable of an object file
        final short mzmaybe = in.getShort();
        if (mzmaybe == 0x5a4d) {
            log("'MZ' detected; nust be an executable");
            coffFile = parseExecutable(in);
        } else {
            // should be a COFF object file
            in.rewind();
            coffFile = parseCoff(in, false);
        }
        return coffFile;
    }

    private CoffObjectFile parseExecutable(ByteBuffer in) {
        final int e_lfanew = in.getInt(0x3c);
        //final long e_lfanew = in.getLong(0x3c);
        in.position(e_lfanew);
        return parseCoff(in, true);
    }

    private CoffObjectFile parseCoff(ByteBuffer in, boolean isPE) {

        final PEHeader hdr;
        final PESection[] sections;
        PESymbolTable symbols = null;

        // parse header
        hdr = PEHeader.build(in);

        // parse optional header
        if (hdr.getOptionalHeaderSize() > 0) {
            int oldposition = in.position();
            //PEOptionalHeader32 ohdr = new PEOptionalHeader32(in);
            // seek to start of section headers, in case optionalheader is padded
            in.position(oldposition + hdr.getOptionalHeaderSize());
        }

        // parse sections
        sections = new PESection[hdr.getNumsections()];
        for (int n = 0; n < hdr.getNumsections(); n++) {
            PESection shdr = PESection.build(in, hdr);
            sections[n] = shdr;
        }

        // parse symbols
        if (hdr.getNumSymbols() > 0) {
            symbols = PESymbolTable.build(in, hdr);
        } // if there's no symbol table at all, keep symbols null, instead of array[0]

        return new CoffObjectFile(hdr, sections, symbols);
    }

    private static void log(final String msg) {
        System.err.println("coffutil: " + msg);
    }

    private static void fatal(final String msg) {
        System.err.println("coffutil: fatal:" + msg);
        System.exit(99);
    }
}
