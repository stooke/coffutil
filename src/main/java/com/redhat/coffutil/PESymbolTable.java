package com.redhat.coffutil;


import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

class PESymbolTable {

    private PESymbol[] symbols;

    PESymbolTable(ByteBuffer in, PEHeader hdr) {
        in.position(hdr.symPtr);
        PESymbol[] syms = new PESymbol[hdr.numSymbols];
        int synnum = 0;
        for (int i=0; i<hdr.numSymbols; i++) {
            syms[synnum] = new PESymbol(in, hdr);
            i += syms[synnum].numaux;
            synnum++;
        }
        symbols = Arrays.copyOf(syms, synnum);
    }

    PESymbol get(int idx) {
        return symbols[idx];
    }

    void dump(PrintStream out) {
        for (PESymbol symbol : symbols) {
            symbol.dump(out);
        }
    }
}


