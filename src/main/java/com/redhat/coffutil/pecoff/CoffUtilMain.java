package com.redhat.coffutil.pecoff;

import com.redhat.coffutil.cv.PECoffObjectFile;
import com.redhat.coffutil.cv.PECoffObjectFileBuilder;
import com.redhat.coffutil.pdb.PDBBuilder;
import com.redhat.coffutil.pdb.PDBFile;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class CoffUtilMain {

    public CoffUtilMain() {
    }

    public void run (String[] args) throws IOException {
        CoffUtilContext ctx = CoffUtilContext.setGlobalContext(args);
        for (final String fn : ctx.inputFiles) {
            ctx.currentInputFilename = fn;
            if (ctx.debug) {
                ctx.log.println("processing " + fn);
            }
            if (fn.endsWith(".pdb")) {
                PDBFile pdbFile = new PDBBuilder().build(fn);
                pdbFile.dump(ctx.out);
            } else {
                PECoffObjectFile cf = new PECoffObjectFileBuilder().build(fn);
                if (ctx.dump) {
                    cf.dump(ctx.out);
                }
                if (ctx.split != null) {
                    ByteBuffer in = Util.readFile(fn);
                    try {
                        int snum = 0;
                        // TODO : write header, string table, reloc tables, symbol tables
                        for (PESection shdr : cf.getSections()) {
                            String sfn = ctx.split + "-" + snum + "-" + shdr.getName();
                            ctx.log.println("dumping " + shdr.getName() + " to " + sfn);
                            BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(sfn));
                            out.write(in.array(), shdr.getRawDataPtr(), shdr.getRawDataSize());
                            out.close();
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        System.exit(99);
                    }
                }
            }
        }
    }
}