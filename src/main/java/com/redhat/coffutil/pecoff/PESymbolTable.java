package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

public class PESymbolTable {

    private final PESymbol[] symbols;

    PESymbolTable(PESymbol[] symbols) {
        this.symbols = symbols;
    }

    public static PESymbolTable build(ByteBuffer in, PEFileHeader hdr) {
        in.position(hdr.getSymPtr());
        PESymbol[] symbols = new PESymbol[hdr.getNumSymbols()];
        for (int i = 0; i< hdr.getNumSymbols(); i++) {
            symbols[i] = new PESymbol(in, hdr, i);
            /* don't save the aux symbol headers separately */
            i += symbols[i].numaux;
        }
        return new PESymbolTable(symbols);
    }

    PESymbol get(int idx) {
        return (idx >= symbols.length) ? null : symbols[idx];
    }

    void dump(PrintStream out) {
        int limit = 100;
        for (PESymbol symbol : symbols) {
            if (symbol != null) {
                symbol.dump(out);
                if (limit-- < 0) break;
            }
        }
    }
}


