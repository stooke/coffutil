package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.Util;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;

public class CVSymbolSectionBuilder implements CVConstants {

    private CoffUtilContext ctx;
    private HashMap<Integer,CVSymbolSection.FileInfo> sourceFiles = new HashMap<>(20);
    private HashMap<Integer,CVSymbolSection.StringInfo> stringTable = new HashMap<>(20);
    private ArrayList<CVSymbolSection.LineInfo> lines = new ArrayList<>(100);
    private HashMap<String, String> env = new HashMap<>(10);
    private int alignment = 0;

    public CVSymbolSectionBuilder() {
        this.ctx = CoffUtilContext.getInstance();
    }

    public CVSymbolSection build(ByteBuffer in, PESection shdr) {
        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        alignment = shdr.alignment();
        ctx.debug("debug$S section %s %s begin=0x%x end=0x%x\n", shdr.getName(), shdr.translateCharacteristics(shdr.getCharacteristics()), sectionBegin, sectionEnd);
        return build(in, sectionBegin, sectionEnd);
    }

    public CVSymbolSection build(ByteBuffer in, int sectionBegin, int sectionEnd) {

        CVSymbolSection symbolSection = new CVSymbolSection(sourceFiles, stringTable, lines, env);

        in.position(sectionBegin);

        final int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            ctx.debug("**** unexpected debug$S signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        boolean skipLineNumbers = !ctx.dumpLinenumbers();

        /* parse symbol debug info */
        while (in.position() < sectionEnd) {

            /* align on 4 bytes */
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            final int startPosition = in.position();

            final int debugCmd = in.getInt();
            final int debugLen = in.getInt();

            final int nextPosition = startPosition + debugLen + 8;
            if (nextPosition > sectionEnd) {
                break;
            }

            ByteBuffer data = ByteBuffer.wrap(in.array(), in.position(), nextPosition - in.position());

            ctx.debug("debug$S: foffset=0x%x soffset=0x%x len=0x%x next=0x%x remain=0x%x cmd=0x%x\n", startPosition,
                        (startPosition - sectionBegin), debugLen, (nextPosition - sectionBegin), (sectionEnd - in.position()), debugCmd);

            String info = null;
            boolean isDebugSLines = false;

            switch (debugCmd) {
                case DEBUG_S_IGNORE: {
                    info = "DEBUG_S_IGNORE";
                    break;
                }
                case DEBUG_S_SYMBOLS: {
                    if (ctx.getDebugLevel() > 0) {
                        info = String.format("DEBUG_S_SYMBOLS(0xf1) soff=0x%x len=0x%x next=0x%x", (in.position() - sectionBegin), debugLen, (nextPosition - sectionBegin));
                        ctx.debug("  0x%04x %s\n", (startPosition - sectionBegin), info);
                        info = null;
                    }
                    this.parseCVSymbolSubsection(in, sectionBegin, debugLen, symbolSection);
                    break;
                }
                case DEBUG_S_LINES: {
                    isDebugSLines = true;
                    int startOffset = in.getInt();
                    short segment = in.getShort();
                    short flags = in.getShort();
                    int cbCon = in.getInt();
                    boolean hasColumns = (flags & 1) == 1;
                    /* unfortunately, startOffset (the function address) is 0 here but added in by a relocation entry later */
                    StringBuilder infoBuilder = null;
                    if (!skipLineNumbers) {
                        infoBuilder = new StringBuilder(String.format("DEBUG_S_LINES(0xf2) startOffset=0x%x:%x flags=0x%x cbCon=0x%x", segment, startOffset, flags, cbCon));
                    }
                    while (in.position() < nextPosition) {
                        int fileId = in.getInt();
                        int nLines = in.getInt();
                        int fileBlock = in.getInt();
                        if (!skipLineNumbers) {
                            infoBuilder.append(String.format("\n    File 0x%04x nLines=%d lineBlockSize=0x%x", fileId, nLines, fileBlock));
                        }
                        /* line number entries */
                        if (hasColumns) {
                            ctx.error("**** can't yet handle columns");
                        }
                        for (int i = 0; i < nLines; i++) {
                            int addr = in.getInt();
                            int lineStuff = in.getInt();
                            int line = lineStuff & 0xffffff;
                            int deltaEnd = (lineStuff & 0x7f000000) >> 24;
                            boolean isStatement = (lineStuff & 0x80000000) != 0;
                            boolean isSpecial = addr == 0xfeefee || addr == 0xf00f00;
                            //if (hasColumns) {
                                // ugh
                            //}
                            CVSymbolSection.LineInfo li = new CVSymbolSection.LineInfo(addr, fileId,  line, isStatement, deltaEnd);
                            if (!skipLineNumbers) {
                                infoBuilder.append(String.format("\n      Line addr=0x%06x delta=%d line=%d isstmt=%s special=%s", addr, deltaEnd, line, isStatement ? "true" : "false", isSpecial ? "true" : "false"));
                            }
                            lines.add(li);
                        }
                    }
                    info = infoBuilder != null ? infoBuilder.toString() : null;
                    break;
                }
                case DEBUG_S_STRINGTABLE: {
                    int cvStringTableOffset = in.position();
                    while (in.position() < nextPosition) {
                        int pos = in.position() - cvStringTableOffset;
                        String s = Util.getString0(in, nextPosition - in.position());
                        stringTable.put(pos, new CVSymbolSection.StringInfo(pos,s));
                    }
                    if (ctx.getDebugLevel() > 1) {
                        StringBuilder infoBuilder = new StringBuilder("DEBUG_S_STRINGTABLE");
                        in.position(cvStringTableOffset);
                        while (in.position() < nextPosition) {
                            int pos = in.position() - cvStringTableOffset;
                            String s = Util.getString0(in, nextPosition - in.position());
                            infoBuilder.append(String.format("\n    0x%04x %s", pos, s));
                        }
                        info = infoBuilder.toString();
                    } else {
                        info = String.format("DEBUG_S_STRINGTABLE nstrings=%d", stringTable.size());
                    }
                    break;
                }
                case DEBUG_S_FILECHKSMS: {
                    /* checksum */
                    int recordStart = in.position();
                    while (in.position() < nextPosition) {
                        int fileId = in.position() - recordStart;
                        int fileStringId = in.getInt();
                        int cb = in.get();
                        int checksumType = in.get();
                        byte[] checksum = new byte[16];
                        in.get(checksum);
                        sourceFiles.put(fileId, new CVSymbolSection.FileInfo(fileId, fileStringId, cb, checksumType, checksum));
                        /* align on 4 bytes */
                        while (((in.position() - sectionBegin) & 3) != 0) {
                            in.get();
                        }
                    }
                    if (ctx.getDebugLevel() > 1) {
                        StringBuilder infoBuilder = new StringBuilder("DEBUG_S_FILECHKSMS");
                        in.position(recordStart);
                        while (in.position() < nextPosition) {
                            int fileId = in.position() - recordStart;
                            int fileStringId = in.getInt();
                            int cb = in.get();
                            int checksumType = in.get();
                            byte[] checksum = new byte[16];
                            in.get(checksum);
                            infoBuilder.append(String.format("\n    DEBUG_S_FILECHKSMS checksum fileid=0x%04x pathString=0x%04x cb=%d type=%d chk=[", fileId, fileStringId, cb, checksumType));
                            for (byte b : checksum) {
                                infoBuilder.append(String.format("%02x", ((int) (b) & 0xff)));
                            }
                            infoBuilder.append("]");
                            /* align on 4 bytes */
                            while (((in.position() - sectionBegin) & 3) != 0) {
                                in.get();
                            }
                        }
                        info = infoBuilder.toString();
                    } else {
                        info = String.format("DEBUG_S_FILECHKSMS numFiles=%d", sourceFiles.size());
                    }
                    break;
                }
                default:
                    info = String.format("(unknown cmd=0x%04x)", debugCmd);
            }
            if (info != null) {
                ctx.debug("  0x%04x %s\n", (startPosition - sectionBegin), info);
                CVSymbolRecord record = new CVSymbolRecord(startPosition - sectionBegin, debugLen, debugCmd, info, data);
                symbolSection.addRecord(record);
            }
            if (nextPosition != in.position()) {
                ctx.error("*** debug$S did not consume exact bytes: want=0x%x current=0x%x", nextPosition - sectionBegin, in.position() - sectionBegin);
            }
            skipLineNumbers = isDebugSLines && !ctx.dumpLinenumbers();
            in.position(nextPosition);
        }

        return symbolSection;
    }

    public void parseCVSymbolSubsection(ByteBuffer in, final int sectionBegin, final int maxlen, CVSymbolSection symbolSection) {
        final int endOfSubsection = in.position() + maxlen;
        while (in.position() < endOfSubsection) {
            final int start = in.position();
            final int len = in.getShort();
            final int cmd = in.getShort();
            final int next = start + len + 2;

            ByteBuffer data = ByteBuffer.wrap(in.array(), in.position(), next - in.position());

            if (ctx != null && ctx.getDebugLevel() > 1) {
                ctx.debug("  debugsubsection: foffset=0x%x soffset=0x%x len=0x%x next=0x%x remain=0x%x cmd=0x%x\n", start,
                        (start - sectionBegin), len, (next - sectionBegin), (endOfSubsection - in.position()), cmd);
            }
            String info;
            switch (cmd) {
                case S_BUILDINFO: {
                    int cvTypeIndex = in.getInt();
                    /* cvTypeIndex is a typeIndex that will be found in the current file */
                    info = String.format("S_BUILDINFO local typeIndex=0x%x", cvTypeIndex);
                    break;
                }
                case S_COMPILE: {
                    int cmachine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = Util.getString0(in, next - in.position());
                    info = String.format("S_COMPILE machine=%d version=%s f1=%d f2=%d f3=%d", cmachine, version, f1, f2, f3);
                    break;
                }
                case S_COMPILE3: {
                    int language = in.get();
                    int cf1 = in.get();
                    boolean hasDebug = (cf1 & 0x80) == 0;
                    /*int cf2 =*/ in.get();
                    in.get(); // padding
                    int machine = in.getShort();
                    int feMajor = in.getShort();
                    int feMinor = in.getShort();
                    int feBuild = ((int)in.getShort()) & 0xffff;
                    int feQFE = in.getShort();
                    int beMajor = in.getShort();
                    int beMinor = in.getShort();
                    int beBuild = ((int)in.getShort()) & 0xffff;
                    int beQFE = in.getShort();
                    String compiler = Util.getString0(in, next - in.position());
                    info = String.format("S_COMPILE3 machine=%d lang=%d debug=%s fe=%d.%d.%d-%d be=%d.%d.%d-%d compiler=%s",
                            machine, language, hasDebug ? "true" : "false", feMajor, feMinor, feBuild, feQFE, beMajor, beMinor, beBuild, beQFE, compiler);
                    break;
                }
                case S_CONSTANT: {
                    int typeindex = in.getInt();
                    int leaf = in.getShort();
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_CONSTANT name=%s typeindex=0x%x leaf=0x%x", name, typeindex, leaf);
                    break;
                }
                case S_END: {
                    info = "S_END";
                    break;
                }
                case S_PROC_ID_END: {
                    info = "S_PROC_ID_END";
                    break;
                }
                case S_ENVBLOCK: {
                    ArrayList<String> strs = new ArrayList<>(20);
                    int flags = in.get(); // should be 0
                    while (in.position() < next) {
                        String s = Util.getString0(in, next - in.position());
                        if (s.length() == 0) {
                            break;
                        }
                        strs.add(s);
                    }
                    for (int i = 0; i < strs.size(); i += 2) {
                        env.put(strs.get(i), strs.get(i+1));
                    }
                    StringBuilder infoBuilder = new StringBuilder(String.format("S_ENVBLOCK flags=0x%x count=%d", flags, strs.size()));
                    for (int i = 0; i < strs.size(); i += 2) {
                        infoBuilder.append(String.format("\n      %s = %s", strs.get(i), strs.get(i + 1)));
                    }
                    info = infoBuilder.toString();
                    break;
                }

                case S_CALLSITEINFO: {
                    int offset = in.getInt();
                    int sectionIndex = in.getShort();
                    int dummy0 = in.getShort();
                    int funcSig = in.getInt();
                    info = String.format("S_CALLSITEINFO section:offset=0x%x:0x%x functionIndex=0x%x", sectionIndex, offset, funcSig);
                    break;
                }

                case S_HEAPALLOCSITE: {
                    int offset = in.getInt();
                    int sectionIndex = in.getShort();
                    int length = in.getShort();
                    int funcSig = in.getInt();
                    info = String.format("S_HEAPALLOCSITE section:offset=0x%x:0x%x length=0x%x functionIndex=0x%x", sectionIndex, offset, length, funcSig);
                    break;
                }

                case S_FRAMEPROC: {
                    String[] x64Regs = { "none", "sp", "bp", "r13"};
                    //CVSymbolSectionBuilder.java
                    int frameLength = in.getInt();
                    int padLen = in.getInt();
                    int padOffset = in.getInt();
                    int saveRegsCount = in.getInt();
                    int ehOffset = in.getInt();
                    int ehSection = in.getShort();
                    int flags = in.getInt();
                    StringBuilder sb = new StringBuilder();
                    if ((flags & 0x0001) != 0) {
                        sb.append(" alloca");
                    }
                    if ((flags & 0x0002) != 0) {
                        sb.append(" setjmp");
                    }
                    if ((flags & 0x0004) != 0) {
                        sb.append(" longjmp");
                    }
                    if ((flags & 0x0008) != 0) {
                        sb.append(" inlineasm");
                    }
                    if ((flags & 0x0010) != 0) {
                        sb.append(" eh");
                    }
                    if ((flags & 0x0020) != 0) {
                        sb.append(" inlinespec");
                    }
                    if ((flags & 0x0040) != 0) {
                        sb.append(" seh");
                    }
                    if ((flags & 0x0080) != 0) {
                        sb.append(" naked");
                    }
                    if ((flags & 0x0100) != 0) {
                        sb.append(" seccheck");
                    }
                    if ((flags & 0x0200) != 0) {
                        sb.append(" asynceh");
                    }
                    if ((flags & 0x0400) != 0) {
                        sb.append(" nostackorder");
                    }
                    if ((flags & 0x0800) != 0) {
                        sb.append(" wasinlined"); // into another function  *****
                    }
                    if ((flags & 0x1000) != 0) {
                        sb.append(" gscheck");
                    }
                    if ((flags & 0x2000) != 0) {
                        sb.append(" safebuffers");
                    }
                    int localBasePointer = (flags >> 14) & 3;
                    sb.append(" lbp=").append(x64Regs[localBasePointer]);
                    int localParamPointer =  (flags >> 16) & 3;
                    sb.append(" pbp=").append(x64Regs[localParamPointer]);
                    if ((flags & 0x040000) != 0) {
                        sb.append(" pogoon");
                    }
                    if ((flags & 0x080000) != 0) {
                        sb.append(" valid_pgo_counts");
                    } else {
                        sb.append(" invalid_pgo_counts");
                    }
                    if ((flags & 0x100000) != 0) {
                        sb.append(" optspeed");
                    }
                    if ((flags & 0x200000) != 0) {
                        sb.append(" guardcf");
                    }
                    if ((flags & 0x400000) != 0) {
                        sb.append(" guardcfw");
                    }
                    /*-
                     *     struct {
                     *         unsigned long   fHasAlloca  :  1;   // function uses _alloca()
                     *         unsigned long   fHasSetJmp  :  1;   // function uses setjmp()
                     *         unsigned long   fHasLongJmp :  1;   // function uses longjmp()
                     *         unsigned long   fHasInlAsm  :  1;   // function uses inline asm
                     *         unsigned long   fHasEH      :  1;   // function has EH states
                     *         unsigned long   fInlSpec    :  1;   // function was speced as inline
                     *         unsigned long   fHasSEH     :  1;   // function has SEH
                     *         unsigned long   fNaked      :  1;   // function is __declspec(naked)
                     *         unsigned long   fSecurityChecks :  1;   // function has buffer security check introduced by /GS.
                     *         unsigned long   fAsyncEH    :  1;   // function compiled with /EHa
                     *         unsigned long   fGSNoStackOrdering :  1;   // function has /GS buffer checks, but stack ordering couldn't be done
                     *         unsigned long   fWasInlined :  1;   // function was inlined within another function
                     *         unsigned long   fGSCheck    :  1;   // function is __declspec(strict_gs_check)
                     *         unsigned long   fSafeBuffers : 1;   // function is __declspec(safebuffers)
                     *         unsigned long   encodedLocalBasePointer : 2;  // record function's local pointer explicitly.
                     *         unsigned long   encodedParamBasePointer : 2;  // record function's parameter pointer explicitly.
                     *         unsigned long   fPogoOn      : 1;   // function was compiled with PGO/PGU
                     *         unsigned long   fValidCounts : 1;   // Do we have valid Pogo counts?
                     *         unsigned long   fOptSpeed    : 1;  // Did we optimize for speed?
                     *         unsigned long   fGuardCF    :  1;   // function contains CFG checks (and no write checks)
                     *         unsigned long   fGuardCFW   :  1;   // function contains CFW checks and/or instrumentation
                     *         unsigned long   pad          : 9;   // must be zero
                     */
                    info = String.format("S_FRAMEPROC len=0x%x padlen=0x%x paddOffset=0x%x regCount=%d flags=0x%x%s eh=0x%x:%x",
                            frameLength, padLen, padOffset, saveRegsCount, flags, sb.toString(), ehSection, ehOffset);
                    break;
                }
                case S_GDATA32: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_GDATA32 name=%s offset=0x%x:%x typeIndex=0x%x", name, segment, offset, typeIndex);
                    break;
                }
                case S_LPROC32_ID:
                case S_LPROC32:
                case S_GPROC32_ID:
                case S_GPROC32: {
                    int pparent = in.getInt();
                    int pend = in.getInt();
                    int pnext = in.getInt();
                    int proclen = in.getInt(); /* length of object code for this procedure */
                    int debugStart = in.getInt();
                    int debugEnd = in.getInt();
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    int flags = in.get();
                    String name = Util.getString0(in, next - in.position());
                    String cmdStr = "(unknown)";
                    switch (cmd) {
                        case S_LPROC32_ID:  cmdStr = "S_LPROC32_ID";    break;
                        case S_LPROC32:     cmdStr = "S_LPROC32";       break;
                        case S_GPROC32_ID:  cmdStr = "S_GPROC32_ID";    break;
                        case S_GPROC32:     cmdStr = "S_GPROC32";       break;
                    }
                    info = String.format("%s name=%s parent=%d pend=%d pnext=%d debugStart=0x%x debugEnd=0x%x offset=0x%x:%x procLen=%d typeIndex=0x%x flags=0x%x",
                                            cmdStr, name, pparent, pend, pnext, debugStart, debugEnd, segment, offset, proclen, typeIndex, flags);
                    break;
                }
                case S_LDATA32: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_LDATA32 name=%s offset=0x%x:%x typeIndex=0x%x", name, segment, offset, typeIndex);
                    break;
                }
                case S_LDATA32_ST: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_LDATA32_ST name=%s offset=0x%x:%x typeIndex=0x%x", name, segment, offset, typeIndex);
                    break;
                }
                case S_OBJNAME: {
                    int signature = in.getInt();
                    String objname = Util.getString0(in, next - in.position());
                    info = String.format("S_OBJNAME objectname=%s signature=0x%x", objname, signature);
                    break;
                }
                case S_REGREL32: {
                    int offset = in.getInt();       /* offset from the register */
                    int typeIndex = in.getInt();    /* type index */
                    int reg = in.getShort();        /* register */
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_REGREL32 name=%s offset=0x%x typeindex=0x%x register=0x%x", name, offset, typeIndex, reg);
                    break;
                }
                case S_LOCAL: {
                    int typeIndex = in.getInt();
                    int localVarFlags = in.getShort();
                    boolean isParam = (localVarFlags & 0x0001) == 0x0001;
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_LOCAL name=%s isParam=%s typeindex=0x%x flags=0x%x", name, isParam, typeIndex, localVarFlags);
                    break;
                }
                case S_DEFRANGE_FRAMEPOINTER_REL: {
                    int offsetToFramPointer = in.getInt();
                    int offsetStart = in.getInt();
                    short isectStart = in.getShort();
                    short cbRange = in.getShort();  // length
                    info = String.format("S_DEFRANGE_FRAMEPOINTER_REL o1=0x%x os=0x%x is=0x%x cbr=0x%x", offsetToFramPointer, offsetStart, isectStart, cbRange);
                    /* some number of gaps: */
                    //    short gapStartOffset = in.getShort();
                    //    short gapcbRange = in.getShort();
                    break;
                }
                case S_SSEARCH: {
                    int offset = in.getInt();
                    int segment = in.getShort();
                    info = String.format("S_SSEARCH offset=0x%x:%x", segment, offset);
                    break;
                }
                case S_UDT: {
                    int typeIndex = in.getInt();
                    String name = Util.getString0(in, next - in.position());
                    info = String.format("S_UDT name=%s typeindex=0x%x", name, typeIndex);
                    break;
                }
                case S_WITH32:
                case S_BLOCK32: {
                    String cmdStr = cmd == S_BLOCK32 ? "S_BLOCK32" : "S_WITH32";
                    //System.out.format("%s %s\n", cmdStr, Util.dumpHex(in, in.position(), len));
                    int parentblock = in.getInt();
                    int blockend = in.getInt();
                    int blocklen = in.getInt();
                    int codeoffset = in.getInt();
                    short segment = in.getShort();
                    String name = Util.getNString(in, next - in.position());
                    info = String.format("%s name=%s parent=0x%x end=0x%x len=0x%x codeoffset=0x%x:%x", cmdStr, name, parentblock, blockend, blocklen, segment, codeoffset);
                    in.position(next);
                    break;
                }
                default:
                    info = String.format("(UNKNOWN) cmd=0x%x", cmd);
                    break;
            }
            if (info != null) {
                ctx.debug("    0x%05x %s\n", (start - sectionBegin), info);
                CVSymbolRecord record = new CVSymbolRecord(start - sectionBegin, len, cmd, "  " + info, data);
                symbolSection.addRecord(record);
            }

            if (alignment > 1) {
                int mask = alignment - 1;
                while (((in.position() - sectionBegin) & mask) != 0) {
                    in.get();
                }
            }

            if (next != in.position()) {
                ctx.error("*** debug$S DEBUG_S_SYMBOLS cmd=0x%x addr0x%05x did not consume exact bytes: want=0x%x current=0x%x align=%d", cmd, start - sectionBegin, sectionBegin, next - sectionBegin, in.position() - sectionBegin, alignment);
            }
            in.position(next);
        }
    }
}
