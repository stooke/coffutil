package com.redhat.coffutil;

import com.redhat.coffutil.ole.OLEFile;
import com.redhat.coffutil.pdb.PDBBuilder;
import com.redhat.coffutil.pecoff.PECoffFileBuilder;

import java.io.File;

class ExeFileBuilderFactory {
    static ExeFileBuilder builderFor(File file) {
        if (file.getName().endsWith(".pdb")) {
            return new PDBBuilder();
        } else if (OLEFile.isOLEFile(file)) {
            return new OLEFile();
        } else {
            return new PECoffFileBuilder();
        }
    }
}
