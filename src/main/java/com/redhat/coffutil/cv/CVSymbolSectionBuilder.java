package com.redhat.coffutil.cv;

import com.redhat.coffutil.coff.PESection;
import com.redhat.coffutil.coff.PEStringTable;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Vector;

class CVSymbolSectionBuilder implements CVConstants {

    private PrintStream out = System.out;
    private boolean debug = true;

    private HashMap<Integer,CVSymbolSection.FileInfo> sourceFiles = new HashMap<>(20);
    private HashMap<Integer,CVSymbolSection.StringInfo> stringTable = new HashMap<>(20);
    private Vector<CVSymbolSection.LineInfo> lines = new Vector<>(100);
    private HashMap<String, String> env = new HashMap<>(10);
    private String objname = null;

    CVSymbolSection build(ByteBuffer in, PESection shdr) {

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug$S signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        if (debug) {
            out.printf("debug$S section begin=0x%x end=0x%x\n", sectionBegin, sectionEnd);
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
                case DEBUG_S_IGNORE:
                    out.println("DEBUG_S_IGNORE");
                    break;
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
                    out.printf("DEBUG_S_LINES(0xf2) startOffset=0x%x segment=0x%d flags=0x%x cbCon=0x%x\n", startOffset, segment, flags, cbCon);
                    while (in.position() < nextPosition) {
                        int fileId = in.getInt();
                        int nLines = in.getInt();
                        int fileBlock = in.getInt();
                        out.printf("  File 0x%04x nLines %d block 0x%x\n", fileId, nLines, fileBlock);
                        // line number entries
                        if (hasColumns) {
                            out.printf("**** can't yet handle columns\n");
                        }
                        for (int i = 0; i < nLines; i++) {
                            int addr = in.getInt();
                            int lineStuff = in.getInt();
                            int line = lineStuff & 0xffffff;
                            int deltaEnd = (lineStuff & 0x7f000000) >> 24;
                            boolean isStatement = (lineStuff & 0x80000000) != 0;
                            boolean isSpecial = addr == 0xfeefee || addr == 0xf00f00;
                            if (hasColumns) {
                                // ugh
                            }
                            CVSymbolSection.LineInfo li = new CVSymbolSection.LineInfo(addr, fileId,  line, isStatement, deltaEnd);
                            out.printf("    Line addr=0x%06x delta=%d line=%d stmt=%s spec=%s\n", addr, deltaEnd, line, isStatement ? "true" : "false", isSpecial ? "true" : "false");
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
            String info = null;
            switch (cmd) {
                case S_COMPILE: {
                    int cmachine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = PEStringTable.getString0(in, next - in.position());
                    info = "  S_COMPILE m=" + cmachine + " v=" + version + " f1=" + f1 + " f2=" + f2 + " f3=" + f3;
                    break;
                }
                case S_COMPILE3: {
                    int language = in.get();
                    int cf1 = in.get();
                    boolean hasDebug = (cf1 & 0x80) == 0;
                    int cf2 = in.get();
                    in.get(); // padding
                    int machine = in.getShort();
                    int feMajor = in.getShort();
                    int feMinor = in.getShort();
                    int feBuild = in.getShort();
                    int feQFE = in.getShort();
                    int beMajor = in.getShort();
                    int beMinor = in.getShort();
                    int beBuild = in.getShort();
                    int beQFE = in.getShort();
                    String compiler = PEStringTable.getString0(in, next - in.position());
                    StringBuilder sb = new StringBuilder(60);
                    sb.append("  S_COMPILE3 machine=").append(machine)
                            .append(" language=").append(language)
                            .append(" debug=").append(hasDebug)
                            .append(" compiler=").append(compiler);
                    info = sb.toString();
                    break;
                }
                case S_CONSTANT: {
                    int typeindex = in.getInt();
                    int leaf = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_CONSTANT name=%s typeindex=0x%x leaf=0x%x\n", name, typeindex, leaf);
                    break;
                }
                case S_END:
                    info = "S_END";
                    break;
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
                    info = "  S_ENVBLOCK flags=" + flags + " count=" + strs.size();
                    for (int i = 0; i < strs.size(); i += 2) {
                        env.put(strs.get(i), strs.get(i+1));
                        if (debug) {
                            info = info + "\nS_ENV  " + strs.get(i) + " = " + strs.get(i + 1);
                        }
                    }
                    break;
                }
                case S_FRAMEPROC: {
                    int framelen = in.getInt();
                    int padLen = in.getInt();
                    int padOffset = in.getInt();
                    int saveRegsCount = in.getInt();
                    int ehOffset = in.getInt();
                    int ehSection = in.getShort();
                    int flags = in.getInt();
                    out.printf("  S_FRAMEPROC len=0x%x padlen=0x%x paddOffset=0x%x regCount=%d flags=0x%x\n", framelen, padLen, padOffset, saveRegsCount, flags);
                    break;
                }
                case S_GDATA32: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_GDATA32 name=%s offset=0x%x segment=0x%x type=0x%x\n", name, offset, segment, typeIndex);
                    break;
                }
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
                    out.printf("  S_GPROC32 name=%s parent=%d startaddr=0x%x end=0x%x len=0x%x offset=0x%x type=0x%x flags=0x%x\n", name, pparent, debugStart, debugEnd, proclen, offset, typeIndex, flags);
                    break;
                }
                case S_LDATA32: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_LDATA32 name=%s offset=0x%x segment=0x%x type=0x%x\n", name, offset, segment, typeIndex);
                    break;
                }
                case S_LDATA32_ST: {
                    int typeIndex = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = "  S_LDATA32_ST name=" + name + " offset=" + offset + " type=" + typeIndex + " segment=" + segment;
                    break;
                }
                case S_OBJNAME:
                    int signature = in.getInt();
                    objname = PEStringTable.getString0(in, next - in.position());
                    info = "  S_OBJNAME objectname=" + objname + " signature=" + signature;
                    break;
                case S_REGREL32: {
                    int offset = in.getInt();
                    int typeIndex = in.getInt();
                    int reg = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_REGREL32 name=%s offset=0x%x type=0x%x reg=0x%x\n", name, offset, typeIndex, reg);
                    break;
                }
                case S_SSEARCH: {
                    int offset = in.getInt();
                    int segment = in.getShort();
                    info = "  S_SSEARCH offset=" + offset + " seg=" + segment;
                    break;
                }
                case S_UDT: {
                    int typeIndex = in.getInt();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_UDT name=%s typeindex=0x%x\n", name, typeIndex);
                    break;
                }
                default:
                    out.printf("  (UNKNOWN cmd=0x%04x)\n", cmd);
                    info = "(UNKNOWN) cmd=" + cmd;
                    break;
            }
            if (info != null) {
                out.println("  " + info);
            }
            if (next != in.position()) {
                out.printf("*** debug$S subsectionn did not consume exact bytes: want=0x%x current=0x%x\n", next - sectionBegin, in.position() - sectionBegin);
            }
            in.position(next);
        }
    }
}