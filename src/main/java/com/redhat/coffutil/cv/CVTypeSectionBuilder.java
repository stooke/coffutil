package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
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

            ByteBuffer data = ByteBuffer.wrap(in.array(), in.position(), nextPosition - in.position());

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
                case LF_MFUNCTION: {
                    int returnType = in.getInt();
                    int classType = in.getInt();
                    int thisType = in.getInt();
                    byte callType = in.get();
                    byte funcAttr = in.get();
                    short paramCount = in.getShort();
                    int argList = in.getInt();
                    int thisAdjustment = in.getInt();
                    info = String.format("LF_MFUNCTION returnType=0x%06x classType=0x%04x thisType=0x%x callType=0x%x funcAttr=0x%x nparam=%d argListType=0x%04x thisAdjust=%d", returnType, classType, thisType, callType, funcAttr, paramCount, argList, thisAdjustment);
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
                case LF_METHODLIST: {
                    info = "LF_METHODLIST: " + Util.dumpHex(in, in.position(), nextPosition - in.position());
                    while (in.position() < nextPosition) {
                        int d1 = in.getShort();
                        int d2 = in.getShort();
                        int typeIndex = in.getInt();
                        info += String.format("\n  d1=%d d2=%d type=0x%04x", d1, d2, typeIndex);
                    }
                    break;
                }
                case LF_VTSHAPE: {
                    int count = in.getShort();
                    info = String.format("LF_VTSHAPE count=%d [%s]", count, Util.dumpHex(in, in.position(), nextPosition - in.position()));
                    break;
                }
                case LF_UNION: {
                    int count = in.getShort();
                    int properties = in.getShort() & 0xffff;
                    int descriptorListIndex = in.getInt();
                    long length = fetchVariable(in);
                    String name = PEStringTable.getString0(in, nextPosition);
                    info = String.format("LF_UNION count=%d attr=0x%x fieldType=0x%04x len=%d %s", count, properties, descriptorListIndex, length, name);
                    break;
                }
                case LF_FIELDLIST: {
                    info = "LF_FIELDLIST:";
                    skipPadding(in);
                    while (in.position() < nextPosition) {
                        int type = in.getShort();
                        switch (type) {
                            case LF_ENUMERATE: {
                                short attr = in.getShort();
                                long l = fetchVariable(in);
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_ENUMERATE type=0x%x attr=0x%x l=%d %s", type, attr, l, name);
                                info += field;
                                break;
                            }
                            case LF_BCLASS: {
                                short attr = in.getShort();
                                int baseTypeIndex = in.getInt();
                                long l = fetchVariable(in);
                              //  String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_BCLASS type=0x%x attr=0x%x baseindex=0x%x len=%d", type, attr, baseTypeIndex, l);
                                info += field;
                                break;
                            }
                            case LF_VBCLASS:
                            case LF_IVBCLASS: {
                                short attr = in.getShort();
                                int n = in.getInt();
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_VBCLASS/LF_IVBCLASS type=0x%x attr=0x%x 0x%x %s", type, attr, n, name);
                                info += field;
                                break;
                            }
                            case LF_MEMBER: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                long l = fetchVariable(in);
                                // TODO - probably need to skip forward by 'l' bytes
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_MEMBER type=0x%04x attr=0x%x typeidx=0x%04x offset=0x%04x %s", type, attr, fieldTypeIdx, l, name);
                                info += field;
                                break;
                            }
                            case LF_VFUNCTAB: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                info += String.format("\n  field LF_VFUNCTAB: type=0x%04x attr=0x%x type=0x%x", type, attr, fieldTypeIdx);
                                break;
                            }
                            case LF_METHOD: {
                                short count = in.getShort();
                                int listIdx = in.getInt();
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_METHOD type=0x%04x count=0x%x typeidx=0x%04x %s",  type, count, listIdx, name);
                                info += field;
                                break;
                            }
                            case LF_ONEMETHOD: {
                                int attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                int vtbleOffset = ((attr & (MPROP_VIRTUAL | MPROP_IVIRTUAL)) != 0) ? in.getInt() : 0;
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_ONEMETHOD type=0x%04x attr=0x%x typeidx=0x%04x voffset=%d %s", type, attr, fieldTypeIdx, vtbleOffset, name);
                                info += field;
                                break;
                            }
                            case LF_NESTTYPE: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field LF_NESTTYPE type=0x%04x attr=0x%x typeidx=0x%04x %s",  type, attr, fieldTypeIdx, name);
                                info += field;
                                break;
                            }
                            default: {
                                short attr = in.getShort();
                                int n = in.getInt();
                                String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  field *** type=0x%04x (unknown) attr=0x%x 0x%x %s\n", type, attr, n, name);
                                info += field;
                                break;
                            }
                        }
                        skipPadding(in);
                    }
                    break;
                }
                case LF_BITFIELD: {
                    int typeIndex = in.getInt();
                    int length = in.get() & 0xff;
                    int pos = in.get() & 0xff;
                    info = String.format("LF_BITFIELD: type=0x%04x length=%d pos=%d", typeIndex, length, pos);
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
                CVTypeRecord typeRecord = new CVTypeRecord(currentTypeIndex, leaf, len, info, data);
                typeSection.addRecord(typeRecord);
            }
            currentTypeIndex++;
            in.position(nextPosition);
        }

        return typeSection;
    }

    private long fetchVariable(ByteBuffer in) {

        int membertype = ((int)in.getShort()) & 0xffff;
        long l = 0;
        switch (membertype) {
            case LF_CHAR:
                l = in.get();
                break;
            case LF_USHORT:
            case LF_SHORT:
                l = in.getShort() & 0xffff;
                break;
            case LF_ULONG:
            case LF_LONG:
                l = in.getInt() & 0xffffffffL;
                break;
            case LF_UQUADWORD:
            case LF_QUADWORD:
                l = in.getLong();
                break;
            default:
                if (membertype < LF_NUMERIC) {
                    l = membertype;
                } else {
                    System.err.format("\nXXX unknown member type 0x%x\n", membertype);
                }
        }
        return l;
    }

    private void skipPadding(ByteBuffer in) {
        while (true) {
            int pad = in.get() & 0xff;
            if (pad < LF_PAD0) {
                in.position(in.position() - 1);
                break;
            }
        }
    }
    private void swap(byte[] b, int idx1, int idx2) {
        byte tmp = b[idx1];
        b[idx1] = b[idx2];
        b[idx2] = tmp;
    }
}
