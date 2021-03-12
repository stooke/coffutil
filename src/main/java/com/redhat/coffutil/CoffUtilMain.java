package com.redhat.coffutil;

import com.redhat.coffutil.pecoff.CoffFile;
import com.redhat.coffutil.pecoff.PECoffFile;
import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.Util;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

class CoffUtilMain {

    CoffUtilMain() {
    }

    void run (String[] args) throws IOException {
        CoffUtilContext ctx = CoffUtilContext.setGlobalContext(args);
        for (final String fn : ctx.inputFiles) {
            ctx.currentInputFilename = fn;
            ctx.info("processing " + fn + "\n");
            File file = new File(fn);
            ExeFile exefile = ExeFileBuilderFactory.builderFor(file).build(file);
            if (ctx.dump) {
                exefile.dump(ctx.getReportStream());
            }
            if (ctx.split != null) {
                if (!(exefile instanceof PECoffFile)) {
                    ctx.fatal("File %s is not a PECOFF file; unable to split", file);
                    return;
                }
                ByteBuffer in = Util.readFile(file);
                CoffFile cf = (CoffFile) exefile;
                try {
                    int snum = 0;
                    /* TODO : write header, string table, reloc tables, symbol tables */
                    for (PESection shdr : cf.getSections()) {
                        String sfn = ctx.split + "-" + snum + "-" + shdr.getName();
                        ctx.debug("dumping " + shdr.getName() + " to " + sfn + "\n");
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
        ctx.cleanup();
    }
}
