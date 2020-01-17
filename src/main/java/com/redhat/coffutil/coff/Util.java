package com.redhat.coffutil.coff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

public abstract class Util {

    static void dumpHex(PrintStream out, ByteBuffer in, int pos, int len) {
        for (; len > 0; len--) {
            out.format("%02x ", in.get(pos++));
        }
    }
}
