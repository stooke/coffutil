package com.redhat.coffutil;

import com.redhat.coffutil.coff.CoffUtilMain;

public class Main {
    public static void main(String[] args) {
        String fn;
       // fn = "c:/tmp/graal-8/openjdk-8u-212_01-src/build/windows-x86_64-normal-server-fastdebug/jdk/objs/javac_objs/main.obj";
        fn = "C:\\tmp\\build-8\\jdk8u\\build\\windows-x86_64-server-release\\jdk\\objs\\javac_objs\\main.obj";
        //fn = "c:/tmp/graal-8/prebuilt_jdk8_vanilla/bin/clhsdb.exe";
        //fn = "c:/tmp/vsjunk/ConsoleApplication1/ConsoleApplication1/x64/Debug/ConsoleApplication1.obj";
        //fn = "c:/tmp/vsjunk/ConsoleApplication1/x64/Debug/ConsoleApplication1.exe";
        //fn = "C:\\tmp\\graal-8\\tmpfilesFromHello_after\\hello.obj";
        //fn = "c:/tmp/graal-8/hellotest/newdebugformat/hello.obj";
        args = args.length > 0 ? args : new String[]{ "-dump", fn };
        new CoffUtilMain().run(args);
    }
}
