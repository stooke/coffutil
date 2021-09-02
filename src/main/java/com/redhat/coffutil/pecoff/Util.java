package com.redhat.coffutil.pecoff;

import java.io.File;
import java.io.IOException;
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

    public static String dumpHex(byte[] in, int count, char sep) {
        StringBuilder sb = new StringBuilder(in.length);
        int n = 0;
        for (byte b : in) {
            sb.append(String.format("%02x", b));
            if (n > 0 && (n % count == 0)) {
                sb.append(sep);
            }
            n++;
        }
        return sb.toString();
    }

    public static ByteBuffer readFile(final File file) throws IOException {
        ByteBuffer buffer;
        RandomAccessFile coffFile = new RandomAccessFile(file,"r");
        FileChannel channel = coffFile.getChannel();
        long fsize = channel.size();
        buffer = ByteBuffer.allocate((int) fsize);
        channel.read(buffer);
        channel.close();
        coffFile.close();
        buffer.position(0);
        return buffer;
    }

    public static String getString0(ByteBuffer in, int maxlen) {
        byte[] buf = new byte[maxlen];
        int len = 0;
        while (maxlen-- > 0) {
            byte b = in.get();
            if (b == 0) {
                break;
            }
            buf[len++] = b;
        }
        return new String(buf, 0, len);
    }

    public static String getNString(ByteBuffer in, int mlen) {
        int maxlen = in.getShort();
        byte[] buf = new byte[maxlen];
        int len = 0;
        while (maxlen-- > 0) {
            byte b = in.get();
            if (b == 0) {
                break;
            }
            buf[len++] = b;
        }
        return new String(buf, 0, len);
    }
}
