package com.redhat.coffutil.coff;

public class CoffUtilMain {

    public CoffUtilMain() {
    }

    public void run (String[] args) {
        CoffUtilContext ctx = CoffUtilContext.setGlobalContext(args);
        for (final String fn : args) {
            ctx.currentInputFilename = fn;
            PECoffObjectFile cf = new PECoffObjectFileBuilder().build(fn);
            cf.dump(ctx.out);
        }
    }
}
