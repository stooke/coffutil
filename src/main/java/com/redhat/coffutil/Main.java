package com.redhat.coffutil;

import java.io.FileNotFoundException;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {
        try {
            new CoffUtilMain().run(args);
        } catch (FileNotFoundException e) {
            System.err.println("coffutil: error: " + e.getLocalizedMessage());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
