package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class PESectionHeader {

    private String name;
    private int virtualSize;
    private int virtualAddress;
    private int rawDataSize;
    private int rawDataPtr;
    private int relocationPtr;
    private int lineNumberPtr;
    private int relocationCount;
    private int lineNumberCount;
    private int characteristics;

    private CoffLineNumberTable lineNumberTable;

    PESectionHeader(ByteBuffer in, PEHeader hdr) {
        int offset = in.position();
        name = PEStringTable.resolve(in, hdr);
        virtualSize = in.getInt();
        virtualAddress = in.getInt();
        rawDataSize = in.getInt();
        rawDataPtr = in.getInt();
        relocationPtr = in.getInt();
        lineNumberPtr = in.getInt();
        relocationCount = in.getShort();
        lineNumberCount = in.getShort();
        characteristics = in.getInt();

        lineNumberTable = new CoffLineNumberTable(in, this, hdr);
    }

    String validate() {
        return null;
    }

    void dump(PrintStream out) {
        String bName = (getName() + "          ").substring(0, PEStringTable.SHORT_LENGTH);
        out.print("section header found: " + bName + " flags=" + getCharacteristics());
        if (getVirtualSize() != 0) {
            out.print(" vaddr,vsize=" + getVirtualAddress() + "," + getVirtualSize());
        }
        if (getRawDataSize() != 0) {
            out.print(" rawPtr,rawSize=" + getRawDataPtr() + "," + getRawDataSize());
        }
        if (getLineNumberCount() != 0) {
            out.print(" linePtr,lineSize=" + getLineNumberPtr() + "," + getLineNumberCount());
        }
        if (getRelocationCount() != 0) {
            out.print(" relocPtr,relocSize=" + getRelocationPtr() + "," + getRelocationCount());
        }
        out.println();
    }

    /**
     // from https://wiki.osdev.org/PE
     struct IMAGE_SECTION_HEADER { // size 40 bytes
     char[8]  name;
     uint32_t virtualSize;
     uint32_t virtualAddress;
     uint32_t rawDataSize;
     uint32_t rawDataPtr;
     uint32_t relocationPtr;
     uint32_t lineNumberPtr;
     uint16_t mNumberOfRealocations;
     uint16_t lineNumberCount;
     uint32_t characteristics;
     };
     ***/
    String getName() {
        return name;
    }

    int getVirtualSize() {
        return virtualSize;
    }

    int getVirtualAddress() {
        return virtualAddress;
    }

    int getRawDataSize() {
        return rawDataSize;
    }

    int getRawDataPtr() {
        return rawDataPtr;
    }

    int getRelocationPtr() {
        return relocationPtr;
    }

    int getLineNumberPtr() {
        return lineNumberPtr;
    }

    int getRelocationCount() {
        return relocationCount;
    }

    int getLineNumberCount() {
        return lineNumberCount;
    }

    int getCharacteristics() {
        return characteristics;
    }

    CoffLineNumberTable getLineNumberTable() {
        return lineNumberTable;
    }
}