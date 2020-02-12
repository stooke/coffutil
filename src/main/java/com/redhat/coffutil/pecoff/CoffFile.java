package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.ExeFile;

import java.io.PrintStream;

public class CoffFile implements ExeFile {

    private final PEFileHeader hdr;
    private final PESection[] sections;
    private final PESymbolTable symbols;

    /* hdr, sections, symbols, cvSymbols, directive */
    public CoffFile(PEFileHeader hdr, PESection[] sections, PESymbolTable symbols) {
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

    public PEFileHeader getHdr() {
        return hdr;
    }

    public PESection[] getSections() {
        return sections;
    }

    public PESymbolTable getSymbols() {
        return symbols;
    }
}
