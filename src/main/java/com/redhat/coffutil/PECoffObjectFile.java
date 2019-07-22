package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Vector;

class PECoffObjectFile {

    private PEHeader hdr;
    private PESectionHeader[] sections;
    private PESymbolTable symbols;

    PECoffObjectFile() {
    }

    void parse(ByteBuffer in) {
        in = in.order(ByteOrder.LITTLE_ENDIAN);
        in.rewind();
        // test if this is an executable of an object file
        final short mzmaybe = in.getShort();
        if (mzmaybe == 0x5a4d) {
            log("'MZ' detected; nust be an executable");
            parseExecutable(in);
        } else {
            // should be a COFF object file
            in.rewind();
            parseCoff(in, false);
        }
    }

    private void parseExecutable(ByteBuffer in) {
        final int e_lfanew = in.getInt(0x3c);
        //final long e_lfanew = in.getLong(0x3c);
        in.position((int) e_lfanew);
        parseCoff(in, true);
    }

    private void parseCoff(ByteBuffer in, boolean isPE) {

        PrintStream out = System.out;

        // parse header
        hdr = new PEHeader(in);
        hdr.validate();
        hdr.dump(out);

        // parse optional header
        if (hdr.optionalHeaderSize > 0) {
            int oldposition = in.position();
            PEOptionalHeader32 ohdr = new PEOptionalHeader32(in);
            ohdr.validate();
            ohdr.dump(out);
            // seek to start of section headers, in case optionalheader is padded
            in.position(oldposition + hdr.optionalHeaderSize);
        }

        // parse sections
        sections = new PESectionHeader[hdr.numsections];
        for (int n = 0; n < hdr.numsections; n++) {
            PESectionHeader shdr = new PESectionHeader(in, hdr);
            sections[n] = shdr;
            shdr.validate();
        }

        // parse symbols
        if (hdr.numSymbols > 0) {
            symbols = new PESymbolTable(in, hdr);
   //         symbols.dump(out);
        }

        // look inside sections
        for (PESectionHeader shdr : sections) {
            final String sectionName = shdr.getName();
            shdr.dump(out);
            switch (sectionName) {
                case ".debug$S":
                    PEDebugTable dt = new PEDebugTable();
                    dt.parse(in, hdr, shdr);
                    break;
                case ".drectve":
                    in.position(shdr.getRawDataPtr());
                    String directive = PEStringTable.getString0(in, shdr.getRawDataSize());
                    if (directive.length() > 100) {
                        directive = directive.substring(0, 100) + "...";
                    }
                    out.println("  link directive: " + directive);
            }
        }
    }

    private void log(final String msg) {
        System.err.println("coffutil: " + msg);
    }

    private void fatal(final String msg) {
        System.err.println("coffutil: fatal:" + msg);
        System.exit(99);
    }

    public PEHeader getHdr() {
        return hdr;
    }

    public PESectionHeader[] getSections() {
        return sections;
    }

    public PESymbolTable getSymbols() {
        return symbols;
    }
}

/*

*** SYMBOLS


(0001E4) S_GPROC32: [0000:00000000], Cb: 00000036, Type:             0x1007, main
         Parent: 00000000, End: 00000000, Next: 00000000
         Debug start: 0000000D, Debug end: 00000031

(000210)  S_FRAMEPROC:
          Frame size = 0x00000028 bytes
          Pad size = 0x00000000 bytes
          Offset of pad in frame = 0x00000000
          Size of callee save registers = 0x00000000
          Address of exception handler = 0000:00000000
          Function info: asynceh invalid_pgo_counts Local=rsp Param=rsp (0x00014200)
(00022E)  S_REGREL32: rsp+00000030, Type:       T_INT4(0074), argc
(000241)  S_REGREL32: rsp+00000038, Type:             0x1005, argv

(000254) S_END


*** LINES

  0000:00000000-00000036, flags = 0000, fileid = 00000000

      1 00000000      2 0000000D      3 00000019      4 00000025
      5 0000002F

*** FILECHKSUMS

FileId  St.Offset  Cb  Type  ChksumBytes
     0  00000001   10  MD5   A9C08DE33413F6FE65E71989B7173954

*** STRINGTABLE

00000000
00000001 c:\tmp\graal-8\hellotest\hello.c

 **/
