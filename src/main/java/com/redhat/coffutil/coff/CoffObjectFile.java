package com.redhat.coffutil.coff;

import java.io.PrintStream;

public class CoffObjectFile {

    private final PEHeader hdr;
    private final PESection[] sections;
    private final PESymbolTable symbols;

    // hdr, sections, symbols, cvSymbols, directive);
    public CoffObjectFile(PEHeader hdr, PESection[] sections, PESymbolTable symbols) {
        this.hdr = hdr;
        this.sections = sections;
        this.symbols = symbols;
    }

    public void dump(PrintStream out) {
        hdr.dump(out);
        for (final PESection shdr : sections) {
            shdr.dump(out, this);
        }
        if (symbols != null) {
            symbols.dump(out);
        }
    }

    public void validate(PrintStream out) {
        hdr.validate();
        for (final PESection shdr : sections) {
            shdr.validate();
        }
        //symbols.validate();
    }

    public PEHeader getHdr() {
        return hdr;
    }

    public PESection[] getSections() {
        return sections;
    }

    public PESymbolTable getSymbols() {
        return symbols;
    }
}
