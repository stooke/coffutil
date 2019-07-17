package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.util.Vector;

public class PEDebugTable {
    // parsing ".debug$S" sections

    private static final int CV_SIGNATURE_C13 = 4;
    private static final int S_COMPILE = 0x0001;
    private static final int S_COMPILE3 = 0x113c;
    private static final int S_OBJNAME = 0x1101;
    private static final int S_SSEARCH = 0x0005;
    private static final int S_ENVBLOCK = 0x113d;
    private static final int S_GPROC32 = 0x1110;
    private static final int S_FRAMEPROC = 0x1012;
    private static final int S_REGREL32 = 0x1111;
    private static final int S_END = 0x0006;

    private static final int DEBUG_S_IGNORE = 0x00;
    private static final int DEBUG_S_SYMBOLS = 0xf1;
    private static final int DEBUG_S_LINES = 0xf2;
    private static final int DEBUG_S_STRINGTABLE = 0xf3;
    private static final int DEBUG_S_FILECHKSMS = 0xf4;

    PEDebugTable() {}

    void parse(ByteBuffer in, PEHeader hdr, PESectionHeader shdr) {

        PrintStream out = System.out;

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpeted debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        int x1 = in.getInt();   // HACK ??
        int x2 = in.getInt();   // ??

        out.println("debug$S section begin=" + sectionBegin + " end=" + sectionEnd + " x1=" + x1 + " x2=" + x2);

        // parse symbol debug info
        while (in.position() < sectionEnd) {
            int startPosition = in.position();
            int len = in.getShort();
            if (len < 0) {
                len = len & 0xffff;
            }
            int nextPosition = startPosition + len + 2;
            if (nextPosition > sectionEnd) {
                // we've overrun somehow
                break;
            }
            int index = in.getShort();
            String info = "";
            switch (index) {
                case S_COMPILE3:
                    info = "S_COMPILE3";
                    break;
                case S_GPROC32:
                    info = "S_GPROC32";
                    break;
                case S_FRAMEPROC:
                    info = "S_FRAMEPROC";
                    break;
                case S_REGREL32:
                    info = "S_REGREL32";
                    break;
                case S_END:
                    info = "S_END";
                    break;
                case S_ENVBLOCK:
                    info = "S_ENVBLOCK";
                    Vector<String> strs = new Vector<>(20);
                    int flags = in.get();
                    while (in.position() < sectionEnd) {
                        String s = PEStringTable.getString0(in, sectionEnd - in.position());
                        if (s.length() == 0) {
                            break;
                        }
                        strs.add(s);
                    }
                    StringBuilder b = new StringBuilder(len);
                    b.append(info);
                    b.append(" flags");
                    b.append(flags);
                    for (int i=0; i<strs.size(); i += 2) {
                        b.append("\n   ");
                        b.append(strs.get(i));
                        b.append(": ");
                        b.append(strs.get(i+1));
                    }
                    info = b.toString();
                    nextPosition = sectionBegin + 0x1e4; // HACK
                    break;
                case S_COMPILE:
                    int machine = in.get();
                    int f1 = in.get();
                    int f2 = in.get();
                    int f3 = in.get();
                    String version = PEStringTable.resolve(in, hdr, len - 2 - 6);
                    info = " m=" + machine + " v=" + version + " f1=" + f1 + " f2=" + f2 + " f3=" + f3;
                    break;
                case S_OBJNAME:
                    int signature = in.getInt();
                    String objname = PEStringTable.resolve(in, hdr, len - 4);
                    info = " objectname=" + objname + " signature=" + signature;
                    break;
                case S_SSEARCH:
                    int offset = in.getInt();
                    int segment = in.getShort();
                    info = " offset=" + offset + " seg=" + segment;
                    break;
            }
            out.println("debug: " + startPosition
                    + " " + (startPosition - sectionBegin)
                    + " len=" + len
                    + " left=" + (sectionEnd - in.position())
                    + " index=" + index
                    + " " + info);
            if (nextPosition > sectionEnd) {
                break;
            }
            in.position(nextPosition);
        }

        out.println("current position " + in.position() + " skipping to " + (sectionBegin + 0x259));
        // parse CodeView info
        in.position(sectionBegin + 0x258); // HACK

        while (in.position() < sectionEnd) {
            int startPos = in.position();
            int subsectionType = in.getInt();
            int subsectionLength = in.getInt();
            int nextSubsection = startPos + subsectionLength + 8;

            if (nextSubsection > sectionEnd) {
                // we've overrun somehow
                break;
            }
            out.println("start=" + startPos + " len=" + subsectionLength + " type=" + subsectionType + " next=" + nextSubsection);
            switch (subsectionType) {
                case DEBUG_S_IGNORE:
                    out.println("DEBUG_S_IGNORE");
                    break;
                case DEBUG_S_SYMBOLS:
                    out.println("DEBUG_S_IGNORE");
                    break;
                case DEBUG_S_LINES:
                    int f02 = in.getInt();
                    int f03 = in.getInt();
                    int a2 = in.getInt();
                    int f04 = in.getInt();
                    int count = in.getInt();
                    int size = in.getInt();
                    out.println("line numbers count=" + count + " a2 = " + a2 + " size=" + size);
                    // line number entries
                    for (int i=0; i<count; i++) {
                        int addr = in.getInt();
                        int lineStuff = in.getInt();
                        int line = lineStuff & 0xffffff;
                        int deltaEnd = (lineStuff & 0x7f000000) >> 24;
                        boolean isStatement = (lineStuff & 0x80000000) != 0;
                        out.println("  line " + line + " addr=" + addr + " stmt=" + isStatement + " delta=" + deltaEnd);
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
                        out.print(" " + ((int)(b) & 0xff));
                    }
                    out.println(" ]");
                    break;
                default:
                    out.println("unknown subsectionType=" + subsectionType);
            }

            in.position(nextSubsection);
        }
    }
}
