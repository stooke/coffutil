package com.redhat.coffutil;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class CoffUtilMain {

    public CoffUtilMain() {
    }

    public void run (String[] args) {
        String fn;
        //fn = "c:/tmp/graal-8/openjdk-8u-212_01-src/build/windows-x86_64-normal-server-fastdebug/jdk/objs/javac_objs/main.obj";
        //fn = "c:/tmp/graal-8/prebuilt_jdk8_vanilla/bin/clhsdb.exe";
        //fn = "c:/tmp/vsjunk/ConsoleApplication1/ConsoleApplication1/x64/Debug/ConsoleApplication1.obj";
        //fn = "c:/tmp/vsjunk/ConsoleApplication1/x64/Debug/ConsoleApplication1.exe";
        //fn = "C:\\tmp\\graal-8\\tmpfilesFromHello_after\\hello.obj";
        fn = "c:/tmp/graal-8/hellotest/newdebugformat/hello.obj";
        fn = args.length == 0 ?  fn  : args[0];

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
