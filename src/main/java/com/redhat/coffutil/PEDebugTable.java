package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Vector;

public class PEDebugTable {
    // parsing ".debug$S" sections

    private static final int CV_SIGNATURE_C13 = 4;
    private static final int S_COMPILE   = 0x0001;
    private static final int S_SSEARCH   = 0x0005;
    private static final int S_END       = 0x0006;
    private static final int S_OBJNAME   = 0x1101;
    private static final int S_LDATA32_ST = 0x1007;
    private static final int S_FRAMEPROC = 0x1012;
    private static final int S_GPROC32   = 0x1110;
    private static final int S_REGREL32  = 0x1111;
    private static final int S_COMPILE3  = 0x113c;
    private static final int S_ENVBLOCK  = 0x113d;

    private static final int DEBUG_S_IGNORE      = 0x00;
    private static final int DEBUG_S_SYMBOLS     = 0xf1;
    private static final int DEBUG_S_LINES       = 0xf2;
    private static final int DEBUG_S_STRINGTABLE = 0xf3;
    private static final int DEBUG_S_FILECHKSMS  = 0xf4;

    private static final String[] languageStrings = { "C", "C++", "Fortran", "masm", "Pascal", "Basic", "COBOL", "LINK", "CVTRES", "CVTPGT", "C#", "VisualBasic", "ILASM", "Java", "JScript", "MSIL", "HSIL" };

    PEDebugTable() {}

    void parse(ByteBuffer in, PEHeader hdr, PESectionHeader shdr) {

        PrintStream out = System.out;

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        int x1 = in.getInt();   // HACK ??
        int x2 = in.getInt();   // ??

        out.printf("debug$S section begin=0x%x end=0x%x x1=0x%x x2=0x%x\n", sectionBegin, sectionEnd, x1, x2);

        // parse symbol debug info
        while (in.position() < sectionEnd) {
            int startPosition = in.position();
            int len = in.getShort();
            if (len < 0) {
                len = len & 0xffff;
            }
            int nextPosition = startPosition + len + 2;
            if (nextPosition > sectionEnd) {
                break;
            }
            int index = in.getShort();
            if (index == 0) {
                break;
            }
            if (len < 4 && index != S_END) {
                break;
            }
            while ((len & 3) != 0) {
                // pad to 4 bytes
                len++;
            }
            String info = "";
            switch (index) {
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
                    String compiler = PEStringTable.getString0(in, nextPosition - in.position());
                    StringBuilder sb = new StringBuilder(60);
                    sb.append("S_COMPILE3 machine=").append(machine)
                            .append(" language=").append(languageStrings[language])
                            .append(" debug=").append(hasDebug)
                            .append(" compiler=").append(compiler);
                    info = sb.toString();
                    break;
                  }
                case S_LDATA32_ST: {
                    int type = in.getInt();
                    int offset = in.getInt();
                    int segment = in.getShort();
                    String name = PEStringTable.getString0(in, sectionEnd - in.position());
                    info = "S_LDATA32_ST name=" + name + " offset=" + offset + " type=" + type + " segment=" + segment;
                    break;
                }
                case S_GPROC32:
                    info = "S_GPROC32";
                    break;
                case S_FRAMEPROC:
                    info = "S_FRAMEPROC";
                    break;
                case S_REGREL32: {
                    info = "S_REGREL32";
                    int offset = in.getInt();
                    int type = in.getInt();
                    int register = in.getShort();
                    String name = PEStringTable.getString0(in, nextPosition - in.position());
                    info = info + " name=" + name + " offset=" + offset + " type=" + type + " reg=" + register;
                    break;
                  }
                case S_END:
                    info = "S_END";
                    break;
                case S_ENVBLOCK: {
                    info = "S_ENVBLOCK";
                    Vector<String> strs = new Vector<>(20);
                    int flags = in.get(); // should be 0
                    while (in.position() < nextPosition) {
                        String s = PEStringTable.getString0(in, nextPosition - in.position());
                        if (s.length() == 0) {
                            break;
                        }
                        strs.add(s);
                    }
                    StringBuilder b = new StringBuilder(len);
                    b.append(info);
                    b.append(" flags");
                    b.append(flags);
                    for (int i = 0; i < strs.size(); i += 2) {
                        b.append("\n   ");
                        b.append(strs.get(i));
                        b.append(": ");
                        b.append(strs.get(i + 1));
                    }
                    info = b.toString();
                   // nextPosition = in.position() - 1; // HACK; is the length somehow wrong?
                    break;
                  }
                case S_COMPILE:
                    int cmachine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = PEStringTable.resolve(in, hdr, len - 2 - 6);
                    info = "S_COMPILE m=" + cmachine + " v=" + version + " f1=" + f1 + " f2=" + f2 + " f3=" + f3;
                    break;
                case S_OBJNAME:
                    int signature = in.getInt();
                    String objname = PEStringTable.getString0(in, nextPosition - in.position());
                    info = "S_OBJNAME objectname=" + objname + " signature=" + signature;
                    break;
                case S_SSEARCH:
                    int offset = in.getInt();
                    int segment = in.getShort();
                    info = "S_OBJNAME offset=" + offset + " seg=" + segment;
                    break;
                default:
                    info = "(UNKNOWN) index=" + index;
                    break;
            }
            out.printf("debug: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d index=0x%x %s\n", startPosition,
                    (startPosition - sectionBegin), len, (nextPosition - sectionBegin), (sectionEnd - in.position()), index, info);
            if (nextPosition != in.position()) {
                out.printf("*** debug did not consume exact bytes: want=0x%x current=0x%x\n", nextPosition - sectionBegin, in.position() - sectionBegin);
            }
           // if (nextPosition > sectionEnd) {
           //     out.printf("*** fell off the end next=0x%x sectionEnd=0x%x\n", (nextPosition-startPosition), len);
           //     break;
           // }
            in.position(nextPosition);
        }

        in.position(in.position() - 4); // backup past the len and index to the start of codevie winformation

        while (((in.position() - sectionBegin) & 3) != 0) {
            //out.printf("... aligning from 0x%x mod=%d\n", in.position() - sectionBegin, (in.position() & 3));
            in.get();
            //out.printf("... aligning to 0x%x\n", in.position() - sectionBegin);
       }

        // parse CodeView info

        while (in.position() < sectionEnd) {

            // align to 4 byte boundary from start of section (even if section is byte-aligned!)
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            int startPos = in.position();
            int subsectionType = in.getInt();
            int subsectionLength = in.getInt();
            int nextSubsection = startPos + subsectionLength + 8;
            out.printf("start=0x%x spos=0x%x len=0x%x type=0x%x next=0x%x\n", startPos, (startPos - sectionBegin), subsectionLength, subsectionType, nextSubsection);
            if (nextSubsection > sectionEnd) {
                // we've overrun somehow
                break;
            }
            switch (subsectionType) {
                case DEBUG_S_IGNORE:
                    out.println("DEBUG_S_IGNORE");
                    break;
                case DEBUG_S_SYMBOLS:
                    out.printf("DEBUG_S_SYMBOLS off=0x%x len=0x%x next=0x%x\n", (in.position() - sectionBegin), subsectionLength, (nextSubsection-sectionBegin));
                    while (in.position() < nextSubsection) {
                        int here = in.position();
                        int len = in.getShort();
                        int cmd = in.getShort();
                        out.printf("   start=0x%x spos=0x%x len=0x%x type=0x%x next=0x%x\n", here, (here - sectionBegin), len, cmd, here + len + 2 - sectionBegin);
                        String ss = null;
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
                                int maxlen = here + len + 2 - in.position();
                                String name = PEStringTable.getString0(in, maxlen);
                                ss = "S_GPROC32 " + name;
                                break;
                            }
                            case S_FRAMEPROC: {
                                ss = "S_FRAMEPROC";
                                int framelen = in.getInt();
                                int padLen = in.getInt();
                                int padOffset = in.getInt();
                                int saveRegsCount = in.getInt();
                                int ehOffset = in.getInt();
                                int ehSection = in.getInt();
                                int flags = in.getInt();
                                break;
                            }
                            case S_REGREL32: {
                                int offset = in.getInt();
                                int type = in.getShort();
                                int reg = in.getShort();
                                int maxlen = here + len + 2 - in.position();
                                String name = PEStringTable.getString0(in, maxlen);
                                ss = "S_REGREL32 " + name;
                                break;
                            }
                            case S_END:
                                ss = "S_END";
                                break;
                            default:
                                ss = "(unknown)";
                        }
                        out.printf("  %s: cmd=0x%x len=0x%x next=0x%x\n", ss, cmd, len, (here + len - sectionBegin));
                        in.position(here + len + 2);
                    }
                    in.position(nextSubsection);
                    break;
                case DEBUG_S_LINES:
                    int f02 = in.getInt();
                    int f03 = in.getInt();
                    int a2 = in.getInt();
                    int f04 = in.getInt();
                    int count = in.getInt();
                    int size = in.getInt();
                    out.println("DEBUG_S_LINES count=" + count + " a2 = " + a2 + " size=" + size);
                    // line number entries
                    for (int i=0; i<count; i++) {
                        int addr = in.getInt();
                        int lineStuff = in.getInt();
                        int line = lineStuff & 0xffffff;
                        int deltaEnd = (lineStuff & 0x7f000000) >> 24;
                        boolean isStatement = (lineStuff & 0x80000000) != 0;
                        out.printf("  line %d addr=0x%x isStmnt=%s delta=0x%x\n", line, addr, (isStatement ? "true" : "false"), deltaEnd);
                    }
                    break;
                case DEBUG_S_STRINGTABLE:
                    int stringNum = 0;
                    while(in.position() < nextSubsection) {
                        String s = PEStringTable.getString0(in, nextSubsection - in.position());
                        out.println("  string " + stringNum + ": \"" + s + "\"");
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

                    out.print("checksum fileid=" + fileid + " chk=[");
                    for (byte b : checksum) {
                        out.printf("%02x", ((int)(b) & 0xff));
                    }
                    out.println("]");
                    break;
                default:
                    out.println("unknown subsectionType=" + subsectionType);
            }
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }
            if (in.position() != nextSubsection) {
                out.printf("*** CV debug section did not consume exact bytes want=0x%x pos=0x%x diff=%d\n", nextSubsection-sectionBegin, in.position()-sectionBegin, (in.position() - nextSubsection));
            }
            in.position(nextSubsection);
        }
    }
}
