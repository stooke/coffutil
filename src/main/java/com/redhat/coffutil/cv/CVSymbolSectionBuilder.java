package com.redhat.coffutil.cv;

import com.redhat.coffutil.pecoff.PESection;
import com.redhat.coffutil.pecoff.PEStringTable;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Vector;

class CVSymbolSectionBuilder implements CVConstants {

    private PrintStream out = System.out;
    private boolean debug = true;
    private PESection peSection;

    private HashMap<Integer,CVSymbolSection.FileInfo> sourceFiles = new HashMap<>(20);
    private HashMap<Integer,CVSymbolSection.StringInfo> stringTable = new HashMap<>(20);
    private Vector<CVSymbolSection.LineInfo> lines = new Vector<>(100);
    private HashMap<String, String> env = new HashMap<>(10);

    CVSymbolSection build(ByteBuffer in, PESection shdr) {

        this.peSection = shdr;
        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug$S signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        if (debug) {
            out.printf("debug$S section %s %s begin=0x%x end=0x%x\n", peSection.getName(), peSection.translateCharacteristics(peSection.getCharacteristics()), sectionBegin, sectionEnd);
        }

        // parse symbol debug info
        while (in.position() < sectionEnd) {

            // align on 4 bytes
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            int startPosition = in.position();
            int debugCmd = in.getInt();
            int debugLen = in.getInt();

            int nextPosition = startPosition + debugLen + 8;
            if (nextPosition > sectionEnd) {
                break;
            }

            if (debug) {
                out.printf("debug$S: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d cmd=0x%x\n", startPosition,
                        (startPosition - sectionBegin), debugLen, (nextPosition - sectionBegin), (sectionEnd - in.position()), debugCmd);
            }

            switch (debugCmd) {
                case DEBUG_S_IGNORE: {
                    out.println("DEBUG_S_IGNORE");
                    break;
                }
                case DEBUG_S_SYMBOLS: {
                    out.printf("DEBUG_S_SYMBOLS off=0x%x len=0x%x next=0x%x\n", (in.position() - sectionBegin), debugLen, (nextPosition - sectionBegin));
                    this.parseSubsection(in, out, sectionBegin, debugLen);
                    break;
                }
                case DEBUG_S_LINES: {
                    int startOffset = in.getInt();
                    short segment = in.getShort();
                    short flags = in.getShort();
                    int cbCon = in.getInt();
                    boolean hasColumns = (flags & 1) == 1;
                    out.printf("DEBUG_S_LINES(0xf2) startOffset=0x%x:%x flags=0x%x cbCon=0x%x\n", segment, startOffset, flags, cbCon);
                    while (in.position() < nextPosition) {
                        int fileId = in.getInt();
                        int nLines = in.getInt();
                        int fileBlock = in.getInt();
                        out.printf("  File 0x%04x nLines=%d fileblock=0x%x\n", fileId, nLines, fileBlock);
                        // line number entries
                        if (hasColumns) {
                            out.print("**** can't yet handle columns\n");
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
                            out.printf("    Line addr=0x%06x delta=%d line=%d isstmt=%s special=%s\n", addr, deltaEnd, line, isStatement ? "true" : "false", isSpecial ? "true" : "false");
                            lines.add(li);
                        }
                    }
                    break;
                }
                case DEBUG_S_STRINGTABLE: {
                    int cvStringTableOffset = in.position();
                    out.println("DEBUG_S_STRINGTABLE");
                    while (in.position() < nextPosition) {
                        int pos = in.position() - cvStringTableOffset;
                        String s = PEStringTable.getString0(in, nextPosition - in.position());
                        stringTable.put(pos, new CVSymbolSection.StringInfo(pos,s));
                    }
                    break;
                }
                case DEBUG_S_FILECHKSMS: {
                    // checksum
                    int recordStart = in.position();
                    while (in.position() < nextPosition) {
                        int fileId = in.position() - recordStart;
                        int fileStringId = in.getInt();
                        int cb = in.get();
                        int checksumType = in.get();
                        byte[] checksum = new byte[16];
                        in.get(checksum);
                        out.printf("DEBUG_S_FILECHKSMS checksum fileid=0x%04x pathString=0x%04x cb=%d type=%d chk=[", fileId, fileStringId, cb, checksumType);
                        for (byte b : checksum) {
                            out.printf("%02x", ((int) (b) & 0xff));
                        }
                        out.println("]");

                        sourceFiles.put(fileId, new CVSymbolSection.FileInfo(fileId, fileStringId, cb, checksumType, checksum));
                        // align on 4 bytes
                        while (((in.position() - sectionBegin) & 3) != 0) {
                            in.get();
                        }
                    }
                    break;
                }
            }
            if (nextPosition != in.position()) {
                out.printf("*** debug$S did not consume exact bytes: want=0x%x current=0x%x\n", nextPosition - sectionBegin, in.position() - sectionBegin);
            }
            in.position(nextPosition);
        }

        return new CVSymbolSection(sourceFiles, stringTable, lines, env);
    }

    private void parseSubsection(ByteBuffer in, PrintStream out, int sectionBegin, int maxlen) {
        int endOfSubsection = in.position() + maxlen;
        while (in.position() < endOfSubsection) {
            int start = in.position();
            int len = in.getShort();
            int cmd = in.getShort();
            int next = start + len + 2;
            if (debug) {
                out.printf("  debugsubsection: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d cmd=0x%x\n", start,
                        (start - sectionBegin), len, (next - sectionBegin), (endOfSubsection - in.position()), cmd);
            }
            String info;
            switch (cmd) {
                case S_BUILDINFO: {
                    int cvTypeIndex = in.getInt();
                    // cvTypeIndex is a typeIndex that will be found in the current file
                    info = String.format("S_BUILDINFO local typeIndex=0x%x", cvTypeIndex);
                    break;
                }
                case S_COMPILE: {
                    int cmachine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = PEStringTable.getString0(in, next - in.position());
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
                    String compiler = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_COMPILE3 machine=%d lang=%d debug=%s fe=%d.%d.%d-%d be=%d.%d.%d-%d compiler=%s",
                            machine, language, hasDebug ? "true" : "false", feMajor, feMinor, feBuild, feQFE, beMajor, beMinor, beBuild, beQFE, compiler);
                    break;
                }
                case S_CONSTANT: {
                    int typeindex = in.getInt();
                    int leaf = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
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
                    Vector<String> strs = new Vector<>(20);
                    int flags = in.get(); // should be 0
                    while (in.position() < next) {
                        String s = PEStringTable.getString0(in, next - in.position());
                        if (s.length() == 0) {
                            break;
                        }
                        strs.add(s);
                    }
                    StringBuilder infoBuilder = new StringBuilder(String.format("S_ENVBLOCK flags=0x%x count=%d\n", flags, strs.size()));
                    for (int i = 0; i < strs.size(); i += 2) {
                        env.put(strs.get(i), strs.get(i+1));
                        if (debug) {
                            infoBuilder.append(String.format("\n      %s = %s", strs.get(i), strs.get(i + 1)));
                        }
                    }
                    info = infoBuilder.toString();
                    break;
                }
                case S_FRAMEPROC: {
                    int frameLength = in.getInt();
                    int padLen = in.getInt();
                    int padOffset = in.getInt();
                    int saveRegsCount = in.getInt();
                    int ehOffset = in.getInt();
                    int ehSection = in.getShort();
                    int flags = in.getInt();
                    info = String.format("S_FRAMEPROC len=0x%x padlen=0x%x paddOffset=0x%x regCount=%d flags=0x%x eh=0x%x:%x", frameLength, padLen, padOffset, saveRegsCount, flags, ehSection, ehOffset);
                    break;
                }
                case S_GDATA32: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
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
                    int proclen = in.getInt();
                    int debugStart = in.getInt();
                    int debugEnd = in.getInt();
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    int flags = in.get();
                    String name = PEStringTable.getString0(in, next - in.position());
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
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_LDATA32 name=%s offset=0x%x:%x typeIndex=0x%x", name, segment, offset, typeIndex);
                    break;
                }
                case S_LDATA32_ST: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_LDATA32_ST name=%s offset=0x%x:%x typeIndex=0x%x", name, segment, offset, typeIndex);
                    break;
                }
                case S_OBJNAME: {
                    int signature = in.getInt();
                    String objname = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_OBJNAME objectname=%s signature=0x%x", objname, signature);
                    break;
                }
                case S_REGREL32: {
                    int offset = in.getInt();       // offset from the register
                    int typeIndex = in.getInt();    // type index
                    int reg = in.getShort();        // register
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_REGREL32 name=%s offset=0x%x typeindex=0x%x register=0x%x", name, offset, typeIndex, reg);
                    break;
                }
                case S_LOCAL: {
                    int typeIndex = in.getInt();
                    int localVarFlags = in.getShort();
                    boolean isParam = (localVarFlags & 0x0001) == 0x0001;
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_LOCAL name=%s isParam=%s typeindex=0x%x flags=0x%x", name, isParam, typeIndex, localVarFlags);
                    break;
                }
                case S_DEFRANGE_FRAMEPOINTER_REL: {
                    int offsetToFramPointer = in.getInt();
                    int offsetStart = in.getInt();
                    short isectStart = in.getShort();
                    short cbRange = in.getShort();  // length
                    info = String.format("S_DEFRANGE_FRAMEPOINTER_REL o1=0x%x os=0x%x is=0x%x cbr=0x%x", offsetToFramPointer, offsetStart, isectStart, cbRange);
                    // some number of gaps:
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
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = String.format("S_UDT name=%s typeindex=0x%x", name, typeIndex);
                    break;
                }
                default:
                    info = String.format("(UNKNOWN) cmd=0x%x", cmd);
                    break;
            }
            if (info != null) {
                out.format("  0x%05x %s\n", (start - sectionBegin), info);
            }

            if (peSection.alignment() > 1) {
                int mask = peSection.alignment() - 1;
                while (((in.position() - sectionBegin) & mask) != 0) {
                    in.get();
                }
            }

            if (next != in.position()) {
                out.printf("*** debug$S subsectionn did not consume exact bytes: want=0x%x current=0x%x\n", next - sectionBegin, in.position() - sectionBegin);
            }
            in.position(next);
        }
    }
}