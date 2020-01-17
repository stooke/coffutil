package com.redhat.coffutil.coff;


import java.io.PrintStream;
import java.nio.ByteBuffer;

class PESymbolTable {

    private final PESymbol[] symbols;

    PESymbolTable(PESymbol[] symbols) {
        this.symbols = symbols;
    }

    static PESymbolTable build(ByteBuffer in, PEHeader hdr) {
        in.position(hdr.getSymPtr());
        PESymbol[] symbols = new PESymbol[hdr.getNumSymbols()];
        for (int i = 0; i< hdr.getNumSymbols(); i++) {
            symbols[i] = new PESymbol(in, hdr, i);
            // don't save the aux symbol headers separately
            i += symbols[i].numaux;
        }
        return new PESymbolTable(symbols);
    }

    PESymbol get(int idx) {
        return (idx >= symbols.length) ? null : symbols[idx];
    }

    void dump(PrintStream out) {
        for (PESymbol symbol : symbols) {
            if (symbol != null) {
                symbol.dump(out);
            }
        }
    }
}


