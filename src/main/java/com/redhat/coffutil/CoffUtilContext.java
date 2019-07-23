package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class CoffUtilContext {

    PrintStream out = System.out;
    PrintStream err = System.err;
    PrintStream log = System.err;

    private String[] inputFiles;
    String currentInputFilename;
    ByteBuffer in;

    boolean debug = false;

    static CoffUtilContext instance = null;

    private CoffUtilContext(String[] args) {
        inputFiles = args;
    }

    static CoffUtilContext setGlobalContext(String[] args) {
        assert( instance == null );
        instance = new CoffUtilContext(args);
        return instance;
    }
}
