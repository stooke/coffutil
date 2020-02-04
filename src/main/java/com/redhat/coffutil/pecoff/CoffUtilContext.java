package com.redhat.coffutil.pecoff;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Vector;

public class CoffUtilContext {

    private PrintStream debugStream = System.err;
    private PrintStream reportStream = System.out;

    // work variables
    String currentInputFilename;
    ByteBuffer in;

    // command line
    Vector<String> inputFiles = new Vector<>();
    private int debugLevel = 1;
    boolean dump = false;
    String split = null;

    private static CoffUtilContext instance = null;

    private CoffUtilContext(String[] args) {
        String prev = null;
        for (String arg : args) {
            if (prev != null) {
                switch (prev) {
                    case "-split": {
                        split = arg;
                        break;
                    }
                    case "-out": {
                        try {
                            new File(arg).delete();
                            debugStream = new PrintStream(arg);
                            reportStream = debugStream;
                        } catch (IOException e) {
                            fatal("error creating %s: %s\n", arg, e.getLocalizedMessage());
                            System.exit(2);
                        }
                    }
                }
                prev = null;
            } else {
                switch (arg) {
                    case "-out":
                        prev = arg;
                        break;
                    case "-split":
                        prev = arg;
                        break;
                    case "-debug":
                    case "-verbose":
                        debugLevel += 1;
                        break;
                    case "-dump":
                        dump = true;
                        break;
                    case "-h":
                    case "--help":
                    case "/?":
                        error("Usage:\ncoffutil [-dump] [-split prefix] [-debug] [-h] inputfiles...");
                        System.exit(0);
                        break;
                    default:
                        if (arg.startsWith("-")) {
                            fatal("unknown argument '" + arg + "'\ntype '-h' for help");
                            System.exit(1);
                        } else {
                            inputFiles.add(arg);
                        }
                        break;
                }
            }
        }
        if (inputFiles.isEmpty()) {
            fatal("no input files specified");
            System.exit(1);
        }
        // spit out a message if there's no action to take
        //if (!(dump || split != null)) {
            //err.println("nothing to do!");
            //System.exit(1);
        //}
    }

    public void cleanup() {
        if (debugStream != System.err) {
            debugStream.close();
        }
        if (reportStream != System.out && reportStream != debugStream) {
            reportStream.close();
        }
    }

    static CoffUtilContext setGlobalContext(String[] args) {
        assert( instance == null );
        instance = new CoffUtilContext(args);
        return instance;
    }

    public int getDebugLevel() {
        return debugLevel;
    }

    public void report(String format, Object ... args)
    {
        if (reportStream != null) {
            reportStream.format(format + "\n", args);
        }
    }

    public PrintStream getReportStream() {
        return reportStream;
    }

    public void debug(String format, Object ... args)
    {
        if (debugLevel >= 2) {
            debugStream.format(format + "\n", args);
        }
    }

    public void info(String format, Object ... args) {
        if (debugLevel >= 1) {
            debugStream.format(format + "\n", args);
        }
    }

    public void error(String format, Object ... args)
    {
        debugStream.format(format + "\n", args);
        System.err.format(format + "\n", args);
    }

    public void fatal(String format, Object ... args)
    {
        debugStream.format(format + "\n", args);
        System.err.format(format + "\n", args);
        System.exit(99);
    }

    public static CoffUtilContext getInstance() {
        return instance;
    }

}
