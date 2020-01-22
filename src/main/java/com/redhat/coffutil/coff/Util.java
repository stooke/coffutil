package com.redhat.coffutil.coff;

import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public abstract class Util {

    public static void dumpHex(PrintStream out, ByteBuffer in, int pos, int len) {
        for (; len > 0; len--) {
            out.format("%02x ", in.get(pos++));
        }
    }

    public static void dumpHex(PrintStream out, byte[] in) {
        for (int i = 0; i < in.length; i++) {
            out.format("%02x ", in[i]);
        }
    }

    public static ByteBuffer readFile(final String fn) {
        ByteBuffer buffer = null;
        try {
            RandomAccessFile coffFile = new RandomAccessFile(fn,"r");
            FileChannel channel = coffFile.getChannel();
            long fsize = channel.size();
            buffer = ByteBuffer.allocate((int) fsize);
            channel.read(buffer);
            channel.close();
            coffFile.close();
        }
        catch (IOException e) {
            System.err.println(e.getLocalizedMessage());
        }
        return buffer;
    }
}
