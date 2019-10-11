package com.redhat.coffutil.coff;

import java.io.PrintStream;
import java.util.Vector;

class PECoffObjectFile {

    private final PEHeader hdr;
    private final PESectionHeader[] sections;
    private final PESymbolTable symbols;
    private final Vector<CVSymbolSection> cvSymbols;
    private final Vector<CVTypeSection> cvTypes;
    private final String directive;

    // hdr, sections, symbols, cvSymbols, directive);
    PECoffObjectFile(PEHeader hdr, PESectionHeader[] sections, PESymbolTable symbols, Vector<CVSymbolSection> cvSymbols, Vector<CVTypeSection> cvTypes, String directive) {
        this.hdr = hdr;
        this.sections = sections;
        this.symbols = symbols;
        this.cvSymbols = cvSymbols;
        this.cvTypes = cvTypes;
        this.directive = directive;
    }

    public void dump(PrintStream out) {
        hdr.dump(out);
        for (final PESectionHeader shdr : sections) {
            shdr.dump(out, this);
        }
        symbols.dump(out);
        for (final CVSymbolSection section : cvSymbols) {
            section.dump(out);
        }
        for (final CVTypeSection section : cvTypes) {
            section.dump(out);
        }
        if (directive != null) {
            out.printf("Link directive: %s\n", directive);
        }
    }

    public void validate(PrintStream out) {
        hdr.validate();
        for (final PESectionHeader shdr : sections) {
            shdr.validate();
        }
        //symbols.validate();
        //cvSymbols.validate();
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

    public Vector<CVSymbolSection> getCvSymbols() { return cvSymbols; }

    public String getDirective() { return directive; }
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
