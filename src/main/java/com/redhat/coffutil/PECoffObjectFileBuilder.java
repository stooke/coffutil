package com.redhat.coffutil;

import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;

class PECoffObjectFileBuilder {

    PrintStream out = System.out;

    PECoffObjectFile build(String fn) {
        ByteBuffer in = readFile(fn);
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
        final PESectionHeader[] sections;
        PESymbolTable symbols = null;
        CVSymbolSection cvSymbols = null;
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
        sections = new PESectionHeader[hdr.getNumsections()];
        for (int n = 0; n < hdr.getNumsections(); n++) {
            PESectionHeader shdr = PESectionHeader.build(in, hdr);
            sections[n] = shdr;
        }

        // parse symbols
        if (hdr.getNumSymbols() > 0) {
            symbols = PESymbolTable.build(in, hdr);
        }

        // look inside sections
        for (PESectionHeader shdr : sections) {
            final String sectionName = shdr.getName();
            // load line numbers and relocations
            switch (sectionName) {
                case ".debug$S":
                    cvSymbols = new CVSymbolSectionBuilder().build(in, shdr);
                    break;
                case ".drectve":
                    in.position(shdr.getRawDataPtr());
                    directive = PEStringTable.getString0(in, shdr.getRawDataSize());
            }
        }

        return new PECoffObjectFile(hdr, sections, symbols, cvSymbols, directive);
    }

    private static ByteBuffer readFile(final String fn) {
        ByteBuffer buffer = null;
        try {
            RandomAccessFile coffFile = new RandomAccessFile(fn,"r");
            FileChannel channel = coffFile.getChannel();
            long fsize = channel.size();
            buffer = ByteBuffer.allocate((int) fsize);
            channel.read(buffer);
            channel.close();
            coffFile.close();
        }
        catch (IOException e)
        {
            fatal(e.getLocalizedMessage());
        }
        return buffer;
    }

    private static void log(final String msg) {
        System.err.println("coffutil: " + msg);
    }

    private static void fatal(final String msg) {
        System.err.println("coffutil: fatal:" + msg);
        System.exit(99);
    }
}
