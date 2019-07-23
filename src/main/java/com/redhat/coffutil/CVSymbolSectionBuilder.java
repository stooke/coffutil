package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Vector;

import static com.redhat.coffutil.CVConstants.CV_SIGNATURE_C13;
import static com.redhat.coffutil.CVConstants.DEBUG_S_FILECHKSMS;
import static com.redhat.coffutil.CVConstants.DEBUG_S_IGNORE;
import static com.redhat.coffutil.CVConstants.DEBUG_S_LINES;
import static com.redhat.coffutil.CVConstants.DEBUG_S_STRINGTABLE;
import static com.redhat.coffutil.CVConstants.DEBUG_S_SYMBOLS;
import static com.redhat.coffutil.CVConstants.S_COMPILE;
import static com.redhat.coffutil.CVConstants.S_COMPILE3;
import static com.redhat.coffutil.CVConstants.S_END;
import static com.redhat.coffutil.CVConstants.S_ENVBLOCK;
import static com.redhat.coffutil.CVConstants.S_FRAMEPROC;
import static com.redhat.coffutil.CVConstants.S_GPROC32;
import static com.redhat.coffutil.CVConstants.S_LDATA32_ST;
import static com.redhat.coffutil.CVConstants.S_OBJNAME;
import static com.redhat.coffutil.CVConstants.S_REGREL32;
import static com.redhat.coffutil.CVConstants.S_SSEARCH;

class CVSymbolSectionBuilder {

    PrintStream out = System.out;
    boolean debug = false;

    Vector<CVSymbolSection.FileInfo> sourceFiles = new Vector<>(20);
    Vector<String> stringTable = new Vector<>(20);
    Vector<CVSymbolSection.LineInfo> lines = new Vector<>(100);
    HashMap<String, String> env = new HashMap<>(10);
    String objname = null;

    CVSymbolSection build(ByteBuffer in, PESectionHeader shdr) {

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
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
                out.printf("debug: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d cmd=0x%x\n", startPosition,
                        (startPosition - sectionBegin), debugLen, (nextPosition - sectionBegin), (sectionEnd - in.position()), debugCmd);
            }

            switch (debugCmd) {
                case DEBUG_S_IGNORE:
                    out.println("DEBUG_S_IGNORE");
                    break;
                case DEBUG_S_SYMBOLS:
                    out.printf("DEBUG_S_SYMBOLS off=0x%x len=0x%x next=0x%x\n", (in.position() - sectionBegin), debugLen, (nextPosition - sectionBegin));
                    this.parseSubsection(in, out, sectionBegin, debugLen);
                    break;
                case DEBUG_S_LINES:
                    int f02 = in.getInt();
                    int f03 = in.getInt();
                    int a2 = in.getInt();
                    int f04 = in.getInt();
                    int count = in.getInt();
                    int size = in.getInt();
                    out.printf("DEBUG_S_LINES count=%d f02=0x%x f03=0x%x a2=0x%x f04=0x%x size=0x%x\n", count, f02, f03, a2, f04, size);
                    // line number entries
                    for (int i = 0; i < count; i++) {
                        int addr = in.getInt();
                        int lineStuff = in.getInt();
                        int line = lineStuff & 0xffffff;
                        int deltaEnd = (lineStuff & 0x7f000000) >> 24;
                        boolean isStatement = (lineStuff & 0x80000000) != 0;
                        CVSymbolSection.LineInfo li = new CVSymbolSection.LineInfo(addr, line, isStatement, deltaEnd);
                        lines.add(li);
                    }
                    break;
                case DEBUG_S_STRINGTABLE:
                    int stringNum = 0;
                    out.println("DEBUG_S_STRINGTABLE");
                    while (in.position() < nextPosition) {
                        String s = PEStringTable.getString0(in, nextPosition - in.position());
                        out.println("  string " + stringNum + ": \"" + s + "\"");
                        stringTable.add(s);
                        stringNum++;
                    }
                    break;
                case DEBUG_S_FILECHKSMS:
                    // checksum
                    int fileid = in.getInt();
                    int cb = in.get();
                    int checksumType = in.get();
                    byte[] checksum = new byte[16];
                    in.get(checksum);

                    out.print("DEBUG_S_FILECHKSMS checksum fileid=" + fileid + " cb=" + cb + " type=" + checksumType + " chk=[");
                    for (byte b : checksum) {
                        out.printf("%02x", ((int) (b) & 0xff));
                    }
                    out.println("]");

                    sourceFiles.add(new CVSymbolSection.FileInfo(fileid, cb, checksumType, checksum));
                    // align on 4 bytes
                    while (((in.position() - sectionBegin) & 3) != 0) {
                        in.get();
                    }
                    break;

            }
            if (nextPosition != in.position()) {
                out.printf("*** debug did not consume exact bytes: want=0x%x current=0x%x\n", nextPosition - sectionBegin, in.position() - sectionBegin);
            }
            in.position(nextPosition);
        }

        // (this is a guess)
        // fix up file names
        for (CVSymbolSection.FileInfo fi : sourceFiles) {
            fi.filename = stringTable.get(fi.fileid);
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
                        (start - sectionBegin), len, (next - sectionBegin), (maxlen - in.position()), cmd);
            }
            String info = null;
            switch (cmd) {
                case S_GPROC32: {
                    int pparent = in.getInt();
                    int pend = in.getInt();
                    int pnext = in.getInt();
                    int proclen = in.getInt();
                    int debugStart = in.getInt();
                    int debugEnd = in.getInt();
                    int type = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    int flags = in.get();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_GPROC32 name=%s parent=%d startaddr=0x%x end=0x%x len=0x%x offset=0x%x type=0x%x flags=0x%x\n", name, pparent, debugStart, debugEnd, proclen, offset, type, flags);
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
                case S_REGREL32: {
                    int offset = in.getInt();
                    int type = in.getInt();
                    int reg = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    out.printf("  S_REGREL32 name=%s offset=0x%x type=0x%x reg=0x%x\n", name, offset, type, reg);
                    break;
                }
                case S_END:
                    info = "S_END";
                    break;
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
                    sb.append("S_COMPILE3 machine=").append(machine)
                            .append(" language=").append(language)
                            .append(" debug=").append(hasDebug)
                            .append(" compiler=").append(compiler);
                    info = sb.toString();
                    break;
                }
                case S_LDATA32_ST: {
                    int type = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, next - in.position());
                    info = "S_LDATA32_ST name=" + name + " offset=" + offset + " type=" + type + " segment=" + segment;
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
                    for (int i = 0; i < strs.size(); i += 2) {
                        env.put(strs.get(i), strs.get(i+1));
                    }
                    info = "S_ENVBLOCK flags=" + flags + " count=" + strs.size();
                    break;
                }
                case S_COMPILE:
                    int cmachine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = PEStringTable.getString0(in, next - in.position());
                    info = "S_COMPILE m=" + cmachine + " v=" + version + " f1=" + f1 + " f2=" + f2 + " f3=" + f3;
                    break;
                case S_OBJNAME:
                    int signature = in.getInt();
                    objname = PEStringTable.getString0(in, next - in.position());
                    info = "S_OBJNAME objectname=" + objname + " signature=" + signature;
                    break;
                case S_SSEARCH:
                    int offset = in.getInt();
                    int segment = in.getShort();
                    info = "S_OBJNAME offset=" + offset + " seg=" + segment;
                    break;
                default:
                    info = "(UNKNOWN) cmd=" + cmd;
                    break;
            }
            if (info != null) {
                out.println("  " + info);
            }
            if (next != in.position()) {
                out.printf("*** subsection debug did not consume exact bytes: want=0x%x current=0x%x\n", next - sectionBegin, in.position() - sectionBegin);
            }
            in.position(next);
        }
    }
}