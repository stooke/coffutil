package com.redhat.coffutil;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class CoffUtilMain {

    public CoffUtilMain() {
    }

    public void run (String[] args) {
        String fn = args.length == 0 ?  "test.obj"  : args[0];
        PECoffObjectFile cf = readCoff(fn);
    }

    private PECoffObjectFile readCoff(final String fn) {
        PECoffObjectFile of = new PECoffObjectFile();
        of.parse(readFile(fn));
        return of;
    }

    private ByteBuffer readFile(final String fn) {
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
        catch (IOException e)
        {
            System.out.println(e);
        }
        return buffer;
    }

    public static void main(String[] args) {
        new CoffUtilMain().run(args);
    }
}
