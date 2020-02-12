package com.redhat.coffutil;

import com.redhat.coffutil.pdb.PDBBuilder;
import com.redhat.coffutil.pecoff.PECoffFileBuilder;

import java.io.File;

class ExeFileBuilderFactory {
    static ExeFileBuilder builderFor(File file) {
        if (file.getName().endsWith(".pdb")) {
            return new PDBBuilder();
        } else {
            return new PECoffFileBuilder();
        }
    }
}
