package com.redhat.coffutil.coff;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Vector;

class CVTypeSectionBuilder implements CVConstants {

    private PrintStream out = System.out;
    private static final boolean debug = true;

    //private Vector<CVTypeRecord> typeRecords = new Vector<>(200);

    public static void dump(String msg, ByteBuffer buffer, int pos, int len) {
        if (buffer == null) return;
        System.out.format("%s0x%06x:", msg, pos);
        for (int i=0; i<len; i++) {
            if ((i & 3) == 0) {
                System.out.print(" ");
            }
            System.out.format("%02x", buffer.get(pos+i));
        }
        System.out.println();
    }

    CVTypeSection build(ByteBuffer in, PESectionHeader shdr) {

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();

        dump("types:", in, sectionBegin, shdr.getRawDataSize());

        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        if (debug) {
            out.printf("debug$T section begin=0x%x end=0x%x\n", sectionBegin, sectionEnd);
        }

        // parse symbol debug info
        while (in.position() < sectionEnd) {

            // align on 4 bytes ?
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            int startPosition = in.position();
            int len = in.getShort();

            int nextPosition = startPosition + len + Short.BYTES;
            if (nextPosition > sectionEnd) {
                break;
            }

            if (debug) {
                out.printf("debug: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d\n", startPosition,
                        (startPosition - sectionBegin), len, (nextPosition - sectionBegin), (sectionEnd - in.position()));
            }

            int leaf = in.getShort();

            switch (leaf) {
                case LF_MODIFIER: {
                    int referentType = in.getInt();
                    short modifiers = in.getShort();
                    boolean isConst     = (modifiers & 0x0001) == 0x0001;
                    boolean isVolatile  = (modifiers & 0x0002) == 0x0002;
                    boolean isUnaligned = (modifiers & 0x0004) == 0x0004;
                    out.printf("LF_MODIFIER len=%d leaf=0x%04x refType=0x%06x modifiers=0x%04x%s%s%s\n", len, leaf, referentType, modifiers, isConst ? " const" : "", isVolatile ? " volatile" : "", isUnaligned ? " unaligned" : "");
                    break;
                }
                case LF_POINTER: {
                    int referentType = in.getInt();
                    int attributes = in.getInt();
                    int kind      =  attributes & 0x00001f;
                    int mode      = (attributes & 0x0000e0) >> 5;
                    int modifiers = (attributes & 0x001f00) >> 8;
                    int size      = (attributes & 0x07e000) >> 13;
                    int flags     = (attributes & 0x380000) >> 19;
                    out.printf("LF_POINTER len=%d leaf=0x%04x refType=0x%06x attrib=0x%06x\n", len, leaf, referentType, attributes);
                    out.printf("           kind=%d mode=%d modifiers=%d size=%d flags=%d\n", kind, mode, modifiers, size, flags);
                    break;
                }
                case LF_PROCEDURE: {
                    int returnType = in.getInt();
                    byte callType = in.get();
                    byte funcAttr = in.get();
                    short paramCount = in.getShort();
                    int argList = in.getInt();
                    boolean instanceConstructor = (funcAttr & 0x2) == 0x2;
                    out.printf("LF_PROCEDURE len=%d leaf=0x%04x returnType=0x%06x callType=0x%x funcAttr=0x%x nparam=%d argListType=0x%04x constructor=%s\n", len, leaf, returnType, callType, funcAttr, paramCount, argList, instanceConstructor ? "true" : "false");
                    break;
                }
                case LF_ARRAY: {
                    int elementType = in.getInt();
                    int indexType = in.getInt();
                    out.printf("LF_ARRAY len=%d leaf=0x%04x elementType=0x%04x indexType=0x%04x\n", len, leaf, elementType, indexType);
                    break;
                }
                case LF_ARGLIST: {
                    int argCount = in.getInt();
                    Vector<Integer> argTypes = new Vector<>(argCount);
                    for (int i=0; i< argCount; i++) {
                        argTypes.add(in.getInt());
                    }
                    out.printf("LF_ARGLIST len=%d leaf=0x%04x count=%d [", len, leaf, argCount);
                    for (int i=0; i< argCount; i++) {
                        out.printf("0x%4x", argTypes.get(i));
                    }
                    out.println();
                    break;
                }
                case LF_TYPESERVER2: {
                    /*  for some very odd reason GUID is stored like this:
                    int guid1 = in.getInt();
                    int guid2 = in.getShort();
                    int guid3 = in.getShort();
                    byte[] guid5[10]
                     */
                    byte[] guid = new byte[16];
                    in.get(guid);
                    swap(guid, 0, 3);
                    swap(guid, 1, 2);
                    swap(guid, 4, 5);
                    swap(guid, 6, 7);

                    int age = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());

                    out.printf("LF_TYPESERVER2 len=%d leaf=0x%04x age=0x%08x, GUID=[", len, leaf, age);
                    for (byte b : guid) {
                        out.printf("%02x", b);
                    }
                    out.printf("] PDB=%s\n", name);
                    break;
                }
            }

            in.position(nextPosition);
        }

        return new CVTypeSection();
    }

    private void swap(byte[] b, int idx1, int idx2) {
        byte tmp = b[idx1];
        b[idx1] = b[idx2];
        b[idx2] = tmp;
    }

}
