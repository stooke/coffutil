package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.msf.HexDump;
import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.PEStringTable;
import com.redhat.coffutil.pecoff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class CVTypeSectionBuilder implements CVConstants {

    private CoffUtilContext ctx = CoffUtilContext.getInstance();

    //private ArrayList<CVTypeRecord> typeRecords = new ArrayList<>(200);

    public static void dump(PrintStream out, String msg, ByteBuffer buffer, int pos, int len) {
        if (buffer == null) return;
        out.format("%s0x%06x:", msg, pos);
        for (int i=0; i<len; i++) {
            if ((i & 3) == 0) {
                out.print(" ");
            }
            out.format("%02x", buffer.get(pos+i));
        }
        out.println();
    }

    public CVTypeSection build(ByteBuffer in, PESection shdr) {
        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            ctx.error("**** unexpected debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        if (ctx.getDebugLevel() > 0) {
            ctx.info("debug$T section begin=0x%x end=0x%x\n", sectionBegin, sectionEnd);
        }
        return build(in, in.position(), sectionEnd);
    }

    public CVTypeSection build(ByteBuffer in, int sectionBegin, int sectionEnd) {

        CVTypeSection typeSection = new CVTypeSection();

        int currentTypeIndex = 0x1000;
        in.position(sectionBegin);

        //dump("types:", in, sectionBegin, shdr.getRawDataSize());

        /* parse symbol debug info */
        while (in.position() < sectionEnd) {

            /* align on 4 bytes ? */
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            int startPosition = in.position();
            int len = in.getShort();

            int nextPosition = startPosition + len + Short.BYTES;
            if (nextPosition > sectionEnd) {
                break;
            }

            if (ctx.getDebugLevel() > 1) {
                ctx.debug("debug: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d\n", startPosition,
                        (startPosition - sectionBegin), len, (nextPosition - sectionBegin), (sectionEnd - in.position()));
            }

            int leaf = in.getShort();
            String info;

            switch (leaf) {
                case LF_MODIFIER: {
                    int referentType = in.getInt();
                    short modifiers = in.getShort();
                    boolean isConst     = (modifiers & 0x0001) == 0x0001;
                    boolean isVolatile  = (modifiers & 0x0002) == 0x0002;
                    boolean isUnaligned = (modifiers & 0x0004) == 0x0004;
                    info = String.format("LF_MODIFIER refType=0x%06x modifiers=0x%04x%s%s%s", referentType, modifiers, isConst ? " const" : "", isVolatile ? " volatile" : "", isUnaligned ? " unaligned" : "");
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
                    info = String.format("LF_POINTER refType=0x%06x attrib=0x%06x kind=%d mode=%d modifiers=%d size=%d flags=%d",
                            referentType, attributes, kind, mode, modifiers, size, flags);
                    break;
                }
                case LF_PROCEDURE: {
                    int returnType = in.getInt();
                    byte callType = in.get();
                    byte funcAttr = in.get();
                    short paramCount = in.getShort();
                    int argList = in.getInt();
                    boolean instanceConstructor = (funcAttr & 0x2) == 0x2;
                    info = String.format("LF_PROCEDURE returnType=0x%06x callType=0x%x funcAttr=0x%x nparam=%d argListType=0x%04x constructor=%s", returnType, callType, funcAttr, paramCount, argList, instanceConstructor ? "true" : "false");
                    break;
                }
                case LF_ARRAY: {
                    int elementType = in.getInt();
                    int indexType = in.getInt();
                    info = String.format("LF_ARRAY elementType=0x%04x indexType=0x%04x", elementType, indexType);
                    break;
                }
                case LF_ARGLIST: {
                    int argCount = in.getInt();
                    ArrayList<Integer> argTypes = new ArrayList<>(argCount);
                    for (int i=0; i< argCount; i++) {
                        argTypes.add(in.getInt());
                    }
                    StringBuilder infoBuilder = new StringBuilder();
                    infoBuilder.append(String.format("LF_ARGLIST count=%d [", argCount));
                    for (int i=0; i< argCount; i++) {
                        infoBuilder.append(String.format(" 0x%04x", argTypes.get(i)));
                    }
                    infoBuilder.append("]");
                    info = infoBuilder.toString();
                    break;
                }
                case LF_FIELDLIST: {
                    /* skip padding */
                    /* this code would be buggy because in.get() is signed */
                   // while (in.get(in.position()) >= LF_PAD0) {
                  //      in.get();
                   // }
                    // instead chat and do an  even pad
                    while ((in.position() & 1) != 0) {
                        in.get();
                    }
                    info = "LF_FIELDLIST:\n";
                    //String dump = new HexDump().makeLines(in, -in.position(), in.position(), len);
                    while (in.position() < nextPosition) {
                        short type = in.getShort();
                        switch (type) {
                            case LF_ENUMERATE: {
                                short attr = in.getShort();
                                // TODO this may be missing info
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("  field type=0x%x attr=0x%x %s\n", type, attr, name);
                                info += field;
                                break;
                            }
                            default: {
                                short attr = in.getShort();
                                int n = in.getInt();
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("  field type=0x%x attr=0x%x 0x%x %s\n", type, attr, n, name);
                                info += field;
                                break;
                            }
                        }


                    }
                    break;
                }
                case LF_BITFIELD: {
                    info = "LF_BITFIELD: " + Util.dumpHex(in, in.position(), len);
                    break;
                }
                //case LF_INTERFACE:
                case LF_CLASS:
                case LF_STRUCTURE: {
                    int count = in.getShort();
                    int properties = in.getShort();
                    int fieldListIndex = in.getInt();
                    int derivedFromIndex = in.getInt();
                    int vshapeIndex = in.getInt();
                    /* TODO name and data */
                    String ln = leaf==LF_CLASS ? "LF_CLASS" : "LF_STRUCTURE";
                    info = String.format("%s count=%d properties=0x%04x fieldListIndex=0x%x derivedFrom=0x%x vshape=0x%x", ln, count, properties, fieldListIndex, derivedFromIndex, vshapeIndex);
                    break;
                }
                case LF_ENUM: {
                    int count = in.getShort();
                    int properties = in.getShort();
                    int underLyingTypeIndex = in.getInt();
                    int fieldListIndex = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    info = String.format("LF_ENUM count=%d properties=0x%04x fieldListIndex=0x%x underLyingTypeIndex=0x%x %s", count, properties, fieldListIndex, underLyingTypeIndex, name);
                    break;
                }
                case LF_FUNC_ID: {
                    int cvTypeIndex = in.getInt();
                    int funcTypeIndex = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    info = String.format("LF_FUNC_ID localscopeIndex=0x%x functionType=0x%x %s", cvTypeIndex, funcTypeIndex, name);
                    break;
                }
                case LF_MFUNC_ID: {
                    int parentTypeIndex = in.getInt();
                    int typeIndex = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    info = String.format("LF_MFUNC_ID parentType=0x%x functionType=0x%x %s", parentTypeIndex, typeIndex, name);
                    break;
                }
                case LF_UDT_SRC_LINE: {
                    int typeIndex = in.getInt();
                    int stringIndex = in.getInt();
                    int line = in.getInt();
                    info = String.format("LF_UDT_SRC_LINE typeIndex=0x%x filename-typeIndex=0x%x line=%d", typeIndex, stringIndex, line);
                    break;
                }
                case LF_STRING_ID: {
                    int cvTypeIndex = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    info = String.format("LF_STRING_ID local typeIndex=0x%x string=%s", cvTypeIndex, name);
                    break;
                }
                case LF_BUILDINFO: {
                    int count = in.getShort();
                    int cwd = in.getInt();
                    int buildTool = in.getInt();
                    int sourceFile = in.getInt();
                    int pdb = in.getInt();
                    int args = in.getInt();
                    info = String.format("LF_BUILDINFO count=%d cwd=0x%x tool=0x%x source=0x%x pdb=0x%x args=0x%x", count, cwd, buildTool, sourceFile, pdb, args);
                    break;
                }
                case LF_TYPESERVER2: {
                    /*
                     * for some very odd reason GUID is stored like this:
                     *    int guid1 = in.getInt();
                     *    int guid2 = in.getShort();
                     *    int guid3 = in.getShort();
                     *    byte[] guid5[10]
                     */
                    byte[] guid = new byte[16];
                    in.get(guid);
                    swap(guid, 0, 3);
                    swap(guid, 1, 2);
                    swap(guid, 4, 5);
                    swap(guid, 6, 7);

                    int age = in.getInt();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    StringBuilder infoBuilder = new StringBuilder(String.format("LF_TYPESERVER2 age=0x%08x, GUID=[", age));
                    for (byte b : guid) {
                        infoBuilder.append(String.format("%02x", b));
                    }
                    infoBuilder.append(String.format("] PDB=%s\n", name));
                    info = infoBuilder.toString();
                    break;
                }
                default: {
                    info = String.format("(unknown 0x%04x)", leaf);
                }
            }

            if (info != null) {
                ctx.debug("  0x%04x 0x%04x 0x%04x %s\n", (startPosition - sectionBegin), currentTypeIndex, leaf, info);
                CVTypeRecord typeRecord = new CVTypeRecord(currentTypeIndex, leaf, len, info, ByteBuffer.wrap(in.array(), startPosition, len));
                typeSection.addRecord(typeRecord);
            }
            currentTypeIndex++;
            in.position(nextPosition);
        }

        return typeSection;
    }

    private void swap(byte[] b, int idx1, int idx2) {
        byte tmp = b[idx1];
        b[idx1] = b[idx2];
        b[idx2] = tmp;
    }
}
