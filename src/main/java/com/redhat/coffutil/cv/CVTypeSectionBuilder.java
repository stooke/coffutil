package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class CVTypeSectionBuilder implements CVConstants {

    private final CoffUtilContext ctx;

    //private ArrayList<CVTypeRecord> typeRecords = new ArrayList<>(200);

    public  CVTypeSectionBuilder(CoffUtilContext ctx) {
        this.ctx = ctx;
    }

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

        ctx.debug("debug$T section begin=0x%x end=0x%x\n", sectionBegin, sectionEnd);
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
            int len = 0xffff & (int)in.getShort();

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
                    info = String.format("LF_MODIFIER refType=0x%04x modifiers=0x%04x%s%s%s", referentType, modifiers, isConst ? " const" : "", isVolatile ? " volatile" : "", isUnaligned ? " unaligned" : "");
                    break;
                }
                case LF_POINTER: {
                    String[] ptrType = { "near16", "far16", "huge", "base-seg", "base-val", "base-segval", "base-addr", "base-segaddr", "base-type", "base-self", "near32", "far32", "64"};
                    String[] memStrs = { "(old)", "data-single", "data-multiple", "data-virtual", "data", "func-single", "mfunc-multiple", "mfunc-virtual", "mfunc"};
                    String[] modeStrs = {"normal", "lvalref", "datamem", "memfunc", "rvalref"};

                    int referentType = in.getInt();
                    int attributes = in.getInt();
                    int kind      =  attributes & 0x00001f;
                    int mode      = (attributes & 0x0000e0) >> 5;
                    int flags1    = (attributes & 0x001f00) >> 8;
                    int size      = (attributes & 0x07e000) >> 13;
                    int flags2     = (attributes & 0x380000) >> 19;
                    StringBuilder sb = new StringBuilder();
                    sb.append((flags1 & 1) != 0 ? "flat32" : "");
                    sb.append((flags1 & 2) != 0 ? " volatile" : "");
                    sb.append((flags1 & 4) != 0 ? " const" : "");
                    sb.append((flags1 & 8) != 0 ? " unaligned" : "");
                    sb.append((flags1 & 16) != 0 ? " restricted" : "");
                    info = String.format("LF_POINTER refType=0x%04x attrib=0x%x kind=%d (%s) mode=%d(%s) flags1=0x%x (%s) size=%d flags2=0x%x",
                            referentType, attributes, kind, ptrType[kind], mode, modeStrs[mode], flags1, sb, size, flags2);
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
                    info = String.format("LF_MFUNCTION returnType=0x%04x classType=0x%04x thisType=0x%04x callType=0x%04x funcAttr=0x%x nparam=%d argListType=0x%04x thisAdjust=%d", returnType, classType, thisType, callType, funcAttr, paramCount, argList, thisAdjustment);
                    break;
                }
                case LF_PROCEDURE: {
                    int returnType = in.getInt();
                    byte callType = in.get();
                    byte funcAttr = in.get();
                    short paramCount = in.getShort();
                    int argList = in.getInt();
                    boolean instanceConstructor = (funcAttr & 0x2) == 0x2;
                    info = String.format("LF_PROCEDURE returnType=0x%04x callType=0x%04x funcAttr=0x%x nparam=%d argListType=0x%04x constructor=%s", returnType, callType, funcAttr, paramCount, argList, instanceConstructor ? "true" : "false");
                    break;
                }
                case LF_ARRAY: {
                    int elementType = in.getInt();
                    int indexType = in.getInt();
                    long size = fetchVariable(in);
                    info = String.format("LF_ARRAY elementType=0x%04x indexType=0x%04x size(total bytes)=%d", elementType, indexType, size);
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
                    StringBuilder infoBuilder = new StringBuilder("LF_METHODLIST: ");
                    infoBuilder.append(Util.dumpHex(in, in.position(), nextPosition - in.position()));
                    while (in.position() < nextPosition) {
                        int attr = in.getShort();
                        int padding = in.getShort();
                        int typeIndex = in.getInt();
                        int vtable_offset = ((attr & MPROP_VSF_MASK) == MPROP_IVIRTUAL || (attr & MPROP_VSF_MASK) == MPROP_PURE_IVIRTUAL) ? in.getInt() : 0;
                        infoBuilder.append(String.format("\n  attr=0x%x (%s) d1=%d vtlb_offset=%d type=0x%04x", attr, fieldString(attr), padding, vtable_offset, typeIndex));
                    }
                    info = infoBuilder.toString();
                    break;
                }
                case LF_UNION: {
                    int count = in.getShort();
                    int attr = in.getShort();
                    int descriptorListIndex = in.getInt();
                    long length = fetchVariable(in);
                    String name = Util.getString0(in, nextPosition);
                    info = String.format("LF_UNION count=%d attr=0x%x (%s) fieldType=0x%04x len=%d %s", count, attr, propertyString(attr), descriptorListIndex, length, name);
                    break;
                }
                case LF_FIELDLIST: {
                    StringBuilder infoBuilder = new StringBuilder("LF_FIELDLIST:");
                    skipPadding(in);
                    int startFieldListPos = in.position();
                    while (in.position() < nextPosition) {
                        int startFieldEntryPos = in.position() - startFieldListPos;
                        int type = in.getShort();
                        switch (type) {
                            case LF_ENUMERATE: {
                                short attr = in.getShort();
                                long value = fetchVariable(in);
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_ENUMERATE(0x%04x) attr=0x%x (%s) value=%d %s", startFieldEntryPos, type, attr, fieldString(attr), value, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_BCLASS: {
                                short attr = in.getShort();
                                int baseTypeIndex = in.getInt();
                                long offset = fetchVariable(in);
                              //  String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_BCLASS(0x%04x) attr=0x%x (%s) baseindex=0x%04x offset=%x", startFieldEntryPos, type, attr, fieldString(attr), baseTypeIndex, offset);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_VBCLASS:
                            case LF_IVBCLASS: {
                                short attr = in.getShort();
                                int vbIndex = in.getInt();
                                int vbPointerIndex = in.getInt();
                                long vbpOffset = fetchVariable(in);
                                long vbteIndex = fetchVariable(in);
                                //String name = PEStringTable.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_VBCLASS/LF_IVBCLASS(0x%04x) attr=0x%x (%s) vbType=0x%04x", startFieldEntryPos, type, attr, fieldString(attr), vbIndex);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_STMEMBER: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_STMEMBER(0x%04x) attr=0x%x (%s) typeidx=0x%04x %s", startFieldEntryPos, type, attr, fieldString(attr), fieldTypeIdx, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_MEMBER: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                long offset = fetchVariable(in);
                                // TODO - probably need to skip forward by 'l' bytes
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_MEMBER(0x%04x) attr=0x%x (%s) typeidx=0x%04x offset=0x%x %s", startFieldEntryPos, type, attr, fieldString(attr), fieldTypeIdx, offset, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_VFUNCTAB: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                infoBuilder.append(String.format("\n  0x%04x field LF_VFUNCTAB(0x%04x) attr=0x%x (%s) type=0x%04x", startFieldEntryPos, type, attr, fieldString(attr), fieldTypeIdx));
                                break;
                            }
                            case LF_METHOD: {
                                short count = in.getShort();
                                int listIdx = in.getInt();
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_METHOD(0x%04x) count=0x%x listidx=0x%04x %s",  startFieldEntryPos, type, count, listIdx, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_ONEMETHOD: {
                                int attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                int vtbleOffset = ((attr & MPROP_VSF_MASK) == MPROP_IVIRTUAL || (attr & MPROP_VSF_MASK) == MPROP_PURE_IVIRTUAL) ? in.getInt() : 0;
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_ONEMETHOD(0x%04x) attr=0x%x (%s) funcIdx=0x%04x voffset=%d %s", startFieldEntryPos, type, attr, fieldString(attr), fieldTypeIdx, vtbleOffset, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_NESTTYPE: {
                                short attr = in.getShort();
                                int fieldTypeIdx = in.getInt();
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field LF_NESTTYPE(0x%04x) attr=0x%x (%s) typeidx=0x%04x %s", startFieldEntryPos, type, attr, fieldString(attr), fieldTypeIdx, name);
                                infoBuilder.append(field);
                                break;
                            }
                            case LF_INDEX: {
                                in.getShort(); /* 2 bytes padding */
                                int idx = in.getInt();
                                String field = String.format("\n  0x%04x field LF_INDEX(0x%04x) typeidx=0x%04x", startFieldEntryPos, type, idx);
                                infoBuilder.append(field);
                                break;
                            }
                            default: {
                                short attr = in.getShort();
                                int n = in.getInt();
                                String name = Util.getString0(in, nextPosition);
                                String field = String.format("\n  0x%04x field *** type=0x%04x (unknown) attr=0x%x (%s) 0x%x %s", startFieldEntryPos, type, attr, fieldString(attr), n, name);
                                infoBuilder.append(field);
                                break;
                            }
                        }
                        skipPadding(in);
                    }
                    info = infoBuilder.toString();
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
                    int attr = in.getShort();
                    int fieldListIndex = in.getInt();
                    int derivedFromIndex = in.getInt();
                    int vshapeIndex = in.getInt();
                    long size = fetchVariable(in);
                    String name = Util.getString0(in, nextPosition);
                    String uniqueName = ((attr & 0x0200) != 0) ? Util.getString0(in, nextPosition) : "";
                    String ln = leaf == LF_CLASS ? "LF_CLASS" : "LF_STRUCTURE";
                    info = String.format("%s count=%d attr=0x%04x (%s) fieldList=0x%04x derivedFrom=0x%04x vshape=0x%x size=%d %s (%s)", ln, count, attr, propertyString(attr), fieldListIndex, derivedFromIndex, vshapeIndex, size, name, uniqueName);
                    break;
                }
                case LF_ENUM: {
                    int count = in.getShort();
                    int attr = in.getShort();
                    int underLyingTypeIndex = in.getInt();
                    int fieldListIndex = in.getInt();
                    String name = Util.getString0(in, nextPosition - in.position());
                    String uniqueName = ((attr & 0x0200) != 0) ? Util.getString0(in, nextPosition) : "";
                    info = String.format("LF_ENUM count=%d attr=0x%04x (%s) fieldListIndex=0x%04x underLyingTypeIndex=0x%04x %s (%s)", count, attr, propertyString(attr), fieldListIndex, underLyingTypeIndex, name, uniqueName);
                    break;
                }
                case LF_FUNC_ID: {
                    int cvTypeIndex = in.getInt();
                    int funcTypeIndex = in.getInt();
                    String name = Util.getString0(in, nextPosition - in.position());
                    info = String.format("LF_FUNC_ID localscopeIndex=0x%x functionType=0x%04x %s", cvTypeIndex, funcTypeIndex, name);
                    break;
                }
                case LF_MFUNC_ID: {
                    int parentTypeIndex = in.getInt();
                    int typeIndex = in.getInt();
                    String name = Util.getString0(in, nextPosition - in.position());
                    info = String.format("LF_MFUNC_ID parentType=0x%04x functionType=0x%04x %s", parentTypeIndex, typeIndex, name);
                    break;
                }
                case LF_UDT_SRC_LINE: {
                    int typeIndex = in.getInt();
                    int stringIndex = in.getInt();
                    int line = in.getInt();
                    info = String.format("LF_UDT_SRC_LINE typeIndex=0x%04x filename-typeIndex=0x%04x line=%d", typeIndex, stringIndex, line);
                    break;
                }
                case LF_UDT_MOD_SRC_LINE: {
                    int typeIndex = in.getInt();
                    int stringIndex = in.getInt();
                    int line = in.getInt();
                    int mod = in.getShort();
                    info = String.format("LF_UDT_MOD_SRC_LINE typeIndex=0x%04x filename-typeIndex=0x%04x line=%d module=%d", typeIndex, stringIndex, line, mod);
                    break;
                }
                case LF_SUBSTR_LIST: {
                    int count = in.getInt();
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < count; i++) {
                        int idx = in.getInt();
                        if (i > 0) {
                            sb.append(",");
                        }
                        sb.append(String.format("0x%04x", idx));
                    }
                    info = String.format("LF_SUBSTR_LIST [%s]", sb);
                    break;
                }
                case LF_STRING_ID: {
                    int substringIndex = in.getInt();
                    String name = Util.getString0(in, nextPosition - in.position());
                    info = String.format("LF_STRING_ID substringIndex=0x%04x string=%s", substringIndex, name);
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
                case LF_VTSHAPE: {
                    int count = in.getShort();
                    String hex = "0123456789abcdef";
                    info = String.format("LF_VTSHAPE count=%d [%s]", count, Util.dumpHex(in, in.position(), nextPosition - in.position()));
                    for (int j = 0; j < count; j++) {
                        int n = in.get(in.position() + j / 2);
                        int b = ((j & 1) == 1 ? n >> 4 : n) & 0xf;
                        info = info + hex.charAt(b) + "-";
                    }
                    break;
                }
                case LF_VFTABLE: {
                    /*
                    0x10d0 : Length = 178, Leaf = 0x151d LF_VFTABLE
                    Type = 0x10cc, base vftable = 0x0000, offset in object layout = 0, len of contents = 160
                    Unique name = ??_7OtherStruct@@6B@
                    0   ?makeDoubleV1@OtherStruct@@UEAANAEAUMyStruct@@PEAV1@@Z
                    1   ?makeDoubleV2@OtherStruct@@UEAANAEAUMyStruct@@PEAV1@@Z
                    2   ??_EOtherStruct@@UEAAPEAXI@Z
                     */
                    int typeIdx = in.getInt();
                    int baseVFTable = in.getInt();
                    int offsetInObject = in.getInt();
                    int contentLen = in.getInt();
                    int endPos = in.position() + contentLen;
                    String typeName = Util.getString0(in, contentLen);
                    info = String.format("LF_VFTABLE type=0x%x (%s) base=0x%x offset=0x%x len=0x%x [", typeIdx, typeName, baseVFTable, offsetInObject, contentLen);
                    while (in.position() < endPos) {
                        String vfn = Util.getString0(in, endPos - in.position());
                        info = info + " " + vfn;
                    }
                    info = info + "]";
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
                    String name = Util.getString0(in, nextPosition - in.position());
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
                if (ctx.dumpTypes()) {
                    ctx.debug("  0x%04x 0x%04x 0x%04x %s\n", (startPosition - sectionBegin), currentTypeIndex, leaf, info);
                }
                CVTypeRecord typeRecord = new CVTypeRecord((startPosition - sectionBegin), currentTypeIndex, leaf, len, info, data);
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
                l = in.getShort() & 0xffff;
                break;
            case LF_SHORT:
                l = in.getShort();
                break;
            case LF_ULONG:
                l = in.getInt() & 0xffffffffL;
                break;
            case LF_LONG:
                l = in.getInt();
                break;
            case LF_UQUADWORD:
            case LF_QUADWORD:
                l = in.getLong();
                break;
            default:
                if (membertype < LF_NUMERIC) {
                    l = membertype;
                } else {
                    ctx.error("unknown member type 0x%x", membertype);
                }
        }
        return l;
    }

    private String fieldString(int properties) {
        StringBuilder sb = new StringBuilder();

        /* Low byte. */
        if ((properties & 0x0003) != 0) {
            String[] aStr = {"", "private", "protected", "public"};
            sb.append(aStr[properties & 0x0003]);
        }
        if ((properties & 0x001c) != 0) {
            int p = (properties & 0x001c) >> 2;
            String[] pStr = {"", " virtual", " static", " friend", " intro", " pure", " intro-pure", " (*7*)"};
            sb.append(pStr[p]);
        }
        if ((properties & 0x0020) != 0) {
            sb.append(" pseudo");
        }
        if ((properties & 0x0040) != 0) {
            sb.append(" final-class");
        }
        if ((properties & 0x0080) != 0) {
            sb.append(" abstract");
        }
        if ((properties & 0x0100) != 0) {
            sb.append(" compgenx");
        }
        if ((properties & 0x0200) != 0) {
            sb.append(" final-method");
        }
        return sb.toString();
    }

    private String propertyString(int properties) {
        StringBuilder sb = new StringBuilder();

        /* Low byte. */
        if ((properties & 0x0001) != 0) {
            sb.append(" packed");
        }
        if ((properties & 0x0002) != 0) {
            sb.append(" ctor");
        }
        if ((properties & 0x0004) != 0) {
            sb.append(" ovlops");
        }
        if ((properties & 0x0008) != 0) {
            sb.append(" isnested");
        }
        if ((properties & 0x0010) != 0) {
            sb.append(" cnested");
        }
        if ((properties & 0x0020) != 0) {
            sb.append(" opassign");
        }
        if ((properties & 0x0040) != 0) {
            sb.append(" opcast");
        }
        if ((properties & 0x0080) != 0) {
            sb.append(" forwardref");
        }

        /* High byte. */
        if ((properties & 0x0100) != 0) {
            sb.append(" scope");
        }
        if ((properties & 0x0200) != 0) {
            sb.append(" hasuniquename");
        }
        if ((properties & 0x0400) != 0) {
            sb.append(" sealed");
        }
        if ((properties & 0x1800) != 0) {
            sb.append(" hfa...");
        }
        if ((properties & 0x2000) != 0) {
            sb.append(" intrinsic");
        }
        if ((properties & 0xc000) != 0) {
            sb.append(" macom...");
        }
        return sb.toString();
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
