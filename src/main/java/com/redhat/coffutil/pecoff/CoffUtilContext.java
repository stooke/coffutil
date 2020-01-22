package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Vector;

class CoffUtilContext {

    PrintStream out = System.out;
    PrintStream err = System.err;
    PrintStream log = System.err;

    // work variables
    String currentInputFilename;
    ByteBuffer in;

    // command line
    Vector<String> inputFiles = new Vector<>();
    boolean debug = false;
    boolean dump = false;
    String split = null;

    static CoffUtilContext instance = null;

    private CoffUtilContext(String[] args) {
        String prev = null;
        for (String arg : args) {
            if (prev != null) {
                switch (prev) {
                    case "-split": {
                        split = arg;
                        break;
                    }
                }
                prev = null;
            } else {
                switch (arg) {
                    case "-split":
                        prev = arg;
                        break;
                    case "-debug":
                    case "-verbose":
                        debug = true;
                        break;
                    case "-dump":
                        dump = true;
                        break;
                    case "-h":
                    case "--help":
                    case "/?":
                        err.println("Usage:\ncoffutil [-dump] [-split prefix] [-debug] [-h] inputfiles...");
                        System.exit(0);
                        break;
                    default:
                        if (arg.startsWith("-")) {
                            err.println("unknown arguement '" + arg + "'\ntype '-h' for help");
                            System.exit(1);
                        } else {
                            inputFiles.add(arg);
                        }
                        break;
                }
            }
        }
        if (inputFiles.isEmpty()) {
            err.println("no input files specified");
            System.exit(1);
        }
        if (!(dump || split != null)) {
            err.println("nothing to do!");
            //System.exit(1);
        }
    }

    static CoffUtilContext setGlobalContext(String[] args) {
        assert( instance == null );
        instance = new CoffUtilContext(args);
        return instance;
    }
}
