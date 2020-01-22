package com.redhat.coffutil;

import com.redhat.coffutil.coff.CoffUtilMain;

public class Main {
    public static void main(String[] args) {
        String fn;
        fn = "./tmp/stuff/listdir.obj";
        fn = "./graalvm-demos/native-list-dir/listdir.exe";
        fn = "c:/tmp/graal-8/helloworld.pdb";
        fn = "c:/tmp/graal-8/vc100.pdb";
        //fn = "c:/tmp/graal-8/helloworld.obj";
        args = args.length > 0 ? args : new String[]{ "-dump", fn };
        new CoffUtilMain().run(args);
    }
}
