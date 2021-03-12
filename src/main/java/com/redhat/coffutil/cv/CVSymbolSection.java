package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.msf.HexDump;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CVSymbolSection {

    /* parsing ".debug$S" sections */

   // private static final String[] languageStrings = { "C", "C++", "Fortran", "masm", "Pascal", "Basic", "COBOL", "LINK", "CVTRES", "CVTPGT", "C#", "VisualBasic", "ILASM", "Java", "JScript", "MSIL", "HSIL" };
    private final List<CVSymbolRecord> records = new ArrayList<>(1000);

    void addRecord(CVSymbolRecord record) {
        records.add(record);
    }

    static class FileInfo {
        int filePos;
        String fileName = null;
        byte[] checksum;
        int fileId;
        int cb;
        int checksumType;

        FileInfo(int filePos, int fileId, int cb, int checksumType, byte[] checksum) {
            this.filePos = filePos;
            this.fileId = fileId;
            this.cb = cb;
            this.checksumType = checksumType;
            this.checksum = checksum;
        }

        void setFileName(String fn) {
            this.fileName = fn;
        }

        String getFileName() {
            return fileName;
        }

        int getFileId() {
            return fileId;
        }

        void dump(PrintStream out) {
            out.format("  fileid:0x%04x path=0x%04x cb=%d chkType=%d checksum=[", filePos, fileId, cb, checksumType);
            for (byte b : checksum) {
                out.format("%02x", ((int) (b) & 0xff));
            }
            out.format("] %s\n", fileName);
            /*
            try {
                String md5 = calculateMD5Sum(filename);
                out.format("calculated=%s", md5);
            } catch (Exception e) {
                e.printStackTrace();
            }*/
        }

        public String calculateMD5Sum(String fn) throws NoSuchAlgorithmException, IOException
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(Files.readAllBytes(Paths.get(fn)));
            byte[] digest = md.digest();
            return DatatypeConverter.printHexBinary(digest).toUpperCase();
        }
    }

    static class LineInfo {
        /* this record requires a backpointer to the function start address */
        /* i.e. 'addr' is an offset from function start */

        int addr;
        int fileId;
        int lineNo;
        boolean isStatement;
        int deltaEnd;
        String fileName;
        LineInfo(int addr, int fileId, int lineNo, boolean isStatement, int deltaEnd) {
            this.addr = addr;
            this.fileId = fileId;
            this.lineNo = lineNo;
            this.isStatement = isStatement;
            this.deltaEnd = deltaEnd;
            this.fileName = null;
        }

        int getFileId() {
            return fileId;
        }

        String getFileName() {
            return fileName;
        }

        void setFileName(String fn) {
            this.fileName = fn;
        }

        void dump(PrintStream out) {
            String fileNameStr = fileName != null ? fileName : "";
            String isStatementStr = isStatement ? " isStatement" : "";
            out.format("  line: 0x%04x deltaEnd=%d%s 0x%04x %s:%d\n", addr, deltaEnd, isStatementStr, fileId, fileNameStr, lineNo);
        }
    }

    static class StringInfo {

        private long offset;
        private String string;

        StringInfo(long offset, String string) {
            this.offset = offset;
            this.string = string;
        }

        long getOffset() {
            return offset;
        }

        public String getString() {
            return string;
        }

        public String toString() {
            return string;
        }
    }

    private final HashMap<Integer, FileInfo> sourceFiles;
    private final HashMap<Integer, StringInfo> stringTable;
    private final ArrayList<LineInfo> lines;
    private final HashMap<String, String> env;

    CVSymbolSection(HashMap<Integer, FileInfo> sourceFiles, HashMap<Integer, StringInfo> stringTable, ArrayList<LineInfo> lines, HashMap<String,String> env) {
        this.sourceFiles = sourceFiles;
        this.stringTable = stringTable;
        this.lines = lines;
        this.env = env;
    }

    public void dump(PrintStream out) {
        for (CVSymbolRecord record : records) {
            out.format("0x%04x 0x%04x len=%-4d %s\n", record.getPos(), record.getCmd(), record.getLen(), record.toString());
            if (CoffUtilContext.getInstance().getDumpHex() && false) {
                String dump = new HexDump().makeLines(record.getData(), -record.getData().position(), record.getData().position(), record.getLen());
                out.print(dump);
            }
        }

        out.format("CV sourcefiles (count=%d):\n", sourceFiles.size());
        if (CoffUtilContext.getInstance().dumpLinenumbers()) {
            for (final FileInfo fi : sourceFiles.values()) {
                StringInfo si = stringTable.get(fi.getFileId());
                if (si != null) {
                    fi.setFileName(si.getString());
                } else {
                    CoffUtilContext.getInstance().error("****** invalid fileid on file %s", fi.toString());
                }
                fi.dump(out);
            }
        }
        if (CoffUtilContext.getInstance().getDebugLevel() > 1) {
            out.println("CV Strings");
            for (final StringInfo si : stringTable.values()) {
                out.format("  0x%04x: \"%s\"\n", si.getOffset(), si.getString());
            }
        }
        if (!env.isEmpty()) {
            out.println("CV env strings:");
            for (Map.Entry<String, String> entry : env.entrySet()) {
                out.format("  %-4s: \"%s\"\n", entry.getKey(), entry.getValue());
            }
        }
        if (!lines.isEmpty()) {
            out.format("CV lines (count=%d):\n", lines.size());
            if (CoffUtilContext.getInstance().dumpLinenumbers()) {
                for (final LineInfo line : lines) {
                    FileInfo fi = sourceFiles.get(line.getFileId());
                    if (fi != null) {
                        line.setFileName(fi.getFileName());
                    } else {
                        CoffUtilContext.getInstance().error("****** invalid fileid on line %s", line.toString());
                    }
                    line.dump(out);
                }
            }
        }
    }
}
