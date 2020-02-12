package com.redhat.coffutil;

import java.io.FileNotFoundException;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        String fn;
        //fn = "./tmp/stuff/listdir.obj";
        //fn = "./graalvm-demos/native-list-dir/listdir.exe";
        //fn = "c:/tmp/graal-8/helloworld.pdb";
        //fn = "c:/tmp/graal-8/vc100.pdb";
        //fn = "c:/tmp/graal-8/helloworld.obj";
        fn = "C:\\tmp\\graal-8\\llvm\\helloworld.o";
        args = args.length > 0 ? args : new String[]{ "-dump", fn };
        try {
            new CoffUtilMain().run(args);
        } catch (FileNotFoundException e) {
            System.err.println("coffutil: error: " + e.getLocalizedMessage());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
