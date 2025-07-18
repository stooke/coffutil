package com.redhat.coffutil;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class CoffUtilContext {

    private PrintStream debugStream = System.err;
    private PrintStream reportStream = System.out;

    /* work variables */
    private String currentInputFilename;

    /* command line */
    private List<String> inputFiles = new ArrayList<>();
    private int debugLevel = 1;
    private boolean dump = false;
    private boolean dumpHex = false;
    private boolean dumpLinenumbers = false;
    private boolean dumpRelocations = false;
    private boolean dumpTypes = false;
    private boolean dumpSymbols = false;
    private boolean reproducibleDump = false;
    private String split = null;

    private static CoffUtilContext instance = null;

    private CoffUtilContext(String[] args) {
        String prev = null;
        for (String arg : args) {
            if (prev != null) {
                switch (prev) {
                    case "--only": {
                        dumpLinenumbers = arg.contains("line");
                        dumpRelocations = arg.contains("reloc");
                        dumpTypes = arg.contains("type");
                        dumpSymbols = arg.contains("sym");
                        break;
                    }
                    case "--split": {
                        split = arg;
                        break;
                    }
                    case "--out": {
                        try {
                            new File(arg).delete();
                            reportStream = new PrintStream(arg);;
                        } catch (IOException e) {
                            fatal("error creating %s: %s", arg, e.getLocalizedMessage());
                            System.exit(2);
                        }
                    }
                }
                prev = null;
            } else {
                switch (arg) {
                    case "--split":
                        prev = "--split";
                        break;
                    case "-l":
                    case "--linenumbers":
                        dump = true;
                        dumpLinenumbers = true;
                        break;
                    case "-R":
                    case "--reproducible":
                        reproducibleDump = true;
                        break;
                    case "-s":
                    case "--symbols":
                        dump = true;
                        dumpSymbols = true;
                        break;
                    case "-t":
                    case "--types":
                        dump = true;
                        dumpTypes = true;
                        break;
                    case "--all":
                        dump = true;
                        dumpRelocations = true;
                        dumpLinenumbers = true;
                        dumpSymbols = true;
                        dumpTypes = true;
                        break;
                    case "--out":
                    case "-o":
                        prev = "--out";
                        break;
                    case "--only":
                        prev = "--only";
                        break;
                    case "--debug":
                    case "--verbose":
                    case "-v":
                        debugLevel += 1;
                        break;
                    case "--dump":
                        dump = true;
                        break;
                    case "--dumphex":
                    case "-x":
                        dump = true;
                        dumpHex = true;
                        break;
                    case "-h":
                    case "--help":
                    case "/?":
                        error("Usage:\ncoffutil [--dump] [-l] [-s] [-t] [--all] [-R] [--only types|line|recloc|sym] [--split prefix] [--debug] [--help] inputfiles... [--out filename]");
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
        /* spit out a message if there's no action to take */
        //if (!(dump || split != null)) {
            //err.println("nothing to do!");
            //System.exit(1);
        //}
    }

    void cleanup() {
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

    public boolean getDumpHex() {
        return dumpHex && dump;
    }

    public void report(String format, Object ... args) {
        if (reportStream != null) {
            reportStream.format(format, args);
        }
    }

    PrintStream getReportStream() {
        return reportStream;
    }

    public void debug(String format, Object ... args) {
        if (debugLevel >= 2) {
            debugStream.format(format, args);
        }
    }

    public void info(String format, Object ... args) {
        if (debugLevel >= 1) {
            debugStream.format(format, args);
        }
    }

    public void error(String format, Object ... args) {
        String nformat = "error: " + format + "\n";
        if (debugStream != System.err) {
            debugStream.format(nformat, args);
        }
        System.err.format(nformat, args);
    }

    public void fatal(String format, Object ... args) {
        String nformat = "fatal: " + format + "\n";
        if (debugStream != System.err) {
            debugStream.format(nformat, args);
        }
        System.err.format(nformat, args);
        System.exit(99);
    }

    public static CoffUtilContext getInstance() {
        return instance;
    }

    public boolean dumpLinenumbers() {
        return dumpLinenumbers;
    }

    public boolean dumpRelocations() {
        return dumpRelocations;
    }

    public boolean dumpTypes() {
        return dumpTypes;
    }

    public boolean dumpSymbols() {
        return dumpSymbols;
    }

    public boolean reproducibleDump() { return reproducibleDump; }

    public String getCurrentInputFilename() {
        return currentInputFilename;
    }

    public void setCurrentInputFilename(String fn) {
        currentInputFilename = fn;
    }

    public List<String> getInputFiles() {
        return inputFiles;
    }

    public boolean isDump() {
        return dump;
    }

    public String getSplit() {
        return split;
    }
}
