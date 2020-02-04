package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.cv.CVSymbolSection;
import com.redhat.coffutil.cv.CVTypeSection;

import java.io.PrintStream;
import java.util.Vector;

public class PECoffFile extends CoffFile {

    private final Vector<CVSymbolSection> cvSymbols;
    private final Vector<CVTypeSection> cvTypes;
    private final String directive;

    // hdr, sections, symbols, cvSymbols, directive);
    PECoffFile(PEFileHeader hdr, PESection[] sections, PESymbolTable symbols, Vector<CVSymbolSection> cvSymbols, Vector<CVTypeSection> cvTypes, String directive) {
        super(hdr, sections, symbols);
        this.cvSymbols = cvSymbols;
        this.cvTypes = cvTypes;
        this.directive = directive;
    }

    public void dump(PrintStream out) {
        super.dump(out);
        for (final CVSymbolSection section : cvSymbols) {
            section.dump(out);
        }
        for (final CVTypeSection section : cvTypes) {
            section.dump(out);
        }
        if (directive != null) {
            out.format("Link directive: %s\n", directive);
        }
    }

    public void validate(PrintStream out) {
        super.validate(out);
        //cvSymbols.validate();
    }

    public Vector<CVSymbolSection> getCvSymbols() { return cvSymbols; }

    public String getDirective() { return directive; }
}
