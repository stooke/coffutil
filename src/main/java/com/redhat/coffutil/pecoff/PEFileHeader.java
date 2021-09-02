package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;

public class PEFileHeader {

    private int pemagic;
    private int pemachine;
    private int numsections;
    private int timeDateStamp;
    private int symPtr;
    private int numSymbols;
    private int optionalHeaderSize;
    private int characteristics;

    private PEFileHeader() {
    }

    public static PEFileHeader build(ByteBuffer in) {
        PEFileHeader hdr = new PEFileHeader();
        hdr._build(in);
        return hdr;
    }

    private void _build(ByteBuffer in) {
        //int offset = in.position();
        pemagic = in.getShort();
        final boolean isPE = (pemagic == 0x4550);
        if (isPE) {
            /* magic is 4 bytes in a PE executable */
            in.getShort();
        }
        pemachine = isPE ? in.getShort() : 0; // 0x8664
        numsections = in.getShort();
        timeDateStamp = in.getInt();
        symPtr = in.getInt();
        numSymbols = in.getInt();
        optionalHeaderSize = in.getShort();
        characteristics = in.getShort();
    }

    String validate() {
        if (pemagic != 0x4550) {  // 0x4550
            return("invalid PE magic: " + pemagic);
        }
        if (pemachine != 0x8664) {
            return("invalid machine: " + pemachine);
        }
        return null;
    }

    void dump(PrintStream out) {
        String exeStr = ((characteristics & 0x2) == 0x2) ? " executable image" : "";
        String x64 = ((characteristics & 0x20) == 0x20) ? " large addess aware" : "";
        out.format("magic = 0x%x machine = 0x%x nsections = %d nsymbols = %d%s%s\n", pemagic, pemachine, numsections, numSymbols, exeStr, x64);
    }

    public int getPemagic() {
        return pemagic;
    }

    public void setPemagic(int pemagic) {
        this.pemagic = pemagic;
    }

    public int getPemachine() {
        return pemachine;
    }

    public void setPemachine(int pemachine) {
        this.pemachine = pemachine;
    }

    public int getNumsections() {
        return numsections;
    }

    public void setNumsections(int numsections) {
        this.numsections = numsections;
    }

    public int getTimeDateStamp() {
        return timeDateStamp;
    }

    public void setTimeDateStamp(int timeDateStamp) {
        this.timeDateStamp = timeDateStamp;
    }

    public int getSymPtr() {
        return symPtr;
    }

    public void setSymPtr(int symPtr) {
        this.symPtr = symPtr;
    }

    public int getNumSymbols() {
        return numSymbols;
    }

    public void setNumSymbols(int numSymbols) {
        this.numSymbols = numSymbols;
    }

    public int getOptionalHeaderSize() {
        return optionalHeaderSize;
    }

    public void setOptionalHeaderSize(int optionalHeaderSize) {
        this.optionalHeaderSize = optionalHeaderSize;
    }

    public int getCharacteristics() {
        return characteristics;
    }

    public void setCharacteristics(int characteristics) {
        this.characteristics = characteristics;
    }
}

