package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.cv.CVSymbolSection;
import com.redhat.coffutil.cv.CVTypeSection;

import java.io.PrintStream;
import java.util.ArrayList;

public class PECoffFile extends CoffFile {

    private final ArrayList<CVSymbolSection> cvSymbols;
    private final ArrayList<CVTypeSection> cvTypes;
    private final PERelocSection relocs;
    private final String directive;

    /* hdr, sections, symbols, cvSymbols, directive */
    PECoffFile(PEFileHeader hdr, PESection[] sections, PESymbolTable symbols, PERelocSection relocs, ArrayList<CVSymbolSection> cvSymbols, ArrayList<CVTypeSection> cvTypes, String directive) {
        super(hdr, sections, symbols);
        this.relocs = relocs;
        this.cvSymbols = cvSymbols;
        this.cvTypes = cvTypes;
        this.directive = directive;
    }

    public void dump(PrintStream out) {
        super.dump(out);

        for (final CVSymbolSection section : cvSymbols) {
            section.dump(out, this);
        }
        for (final CVTypeSection section : cvTypes) {
            section.dump(out);
        }
        if (directive != null) {
            out.format("Link directive: %s\n", directive);
        }
        if (CoffUtilContext.getInstance().dumpRelocations() && relocs != null) {
            relocs.dump(out, Integer.MAX_VALUE);
        }
    }

    public void validate(PrintStream out) {
        super.validate(out);
        //cvSymbols.validate();
    }

    public ArrayList<CVSymbolSection> getCvSymbols() { return cvSymbols; }

    public String getDirective() { return directive; }

    public PERelocSection getRelocs() {
        return relocs;
    }
}
