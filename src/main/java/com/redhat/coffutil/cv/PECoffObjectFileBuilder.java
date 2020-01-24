package com.redhat.coffutil.cv;

import com.redhat.coffutil.pecoff.CoffObjectFileBuilder;
import com.redhat.coffutil.pecoff.PEHeader;
import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.PEStringTable;
import com.redhat.coffutil.pecoff.PESymbolTable;
import com.redhat.coffutil.pecoff.Util;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Vector;

public class PECoffObjectFileBuilder extends CoffObjectFileBuilder {

    public PECoffObjectFile build(String fn) throws IOException {
        ByteBuffer in = Util.readFile(fn);
        return build(in);
    }

    private PECoffObjectFile build(ByteBuffer in) {
        final PECoffObjectFile coffFile;
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

    private PECoffObjectFile parseExecutable(ByteBuffer in) {
        final int e_lfanew = in.getInt(0x3c);
        //final long e_lfanew = in.getLong(0x3c);
        in.position(e_lfanew);
        return parseCoff(in, true);
    }

    private PECoffObjectFile parseCoff(ByteBuffer in, boolean isPE) {

        final PEHeader hdr;
        final PESection[] sections;
        PESymbolTable symbols = null;
        Vector<CVSymbolSection> cvSymbols = new Vector<>(10);
        Vector<CVTypeSection> cvTypes = new Vector<>(10);
        String directive = null;

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

        // look inside sections
        for (PESection shdr : sections) {
            final String sectionName = shdr.getName();
            // load line numbers and relocations
            switch (sectionName) {
                case ".debug$S":
                    cvSymbols.add(new CVSymbolSectionBuilder().build(in, shdr));
                    break;
                case ".debug$T":
                    cvTypes.add(new CVTypeSectionBuilder().build(in, shdr));
                    break;
                case ".drectve":
                    in.position(shdr.getRawDataPtr());
                    directive = PEStringTable.getString0(in, shdr.getRawDataSize());
            }
        }

        return new PECoffObjectFile(hdr, sections, symbols, cvSymbols, cvTypes, directive);
    }

    private static void log(final String msg) {
        System.err.println("coffutil: " + msg);
    }

    private static void fatal(final String msg) {
        System.err.println("coffutil: fatal:" + msg);
        System.exit(99);
    }
}
