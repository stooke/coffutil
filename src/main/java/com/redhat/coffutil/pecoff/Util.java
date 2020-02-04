package com.redhat.coffutil.pecoff;

import java.io.IOException;
import java.io.PrintStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public abstract class Util {

    public static String dumpHex(ByteBuffer in, int pos, int len) {
        StringBuilder sb = new StringBuilder(len);
        for (; len > 0; len--) {
            sb.append(String.format("%02x ", in.get(pos++)));
        }
        return sb.toString();
    }

    public static String dumpHex(byte[] in) {
        StringBuilder sb = new StringBuilder(in.length);
        for (byte b : in) {
            sb.append(String.format("%02x ", b));
        }
        return sb.toString();
    }

    public static ByteBuffer readFile(final String fn) throws IOException {
        ByteBuffer buffer = null;
        RandomAccessFile coffFile = new RandomAccessFile(fn,"r");
        FileChannel channel = coffFile.getChannel();
        long fsize = channel.size();
        buffer = ByteBuffer.allocate((int) fsize);
        channel.read(buffer);
        channel.close();
        coffFile.close();
        return buffer;
    }
}
