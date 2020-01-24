package com.redhat.coffutil.cv;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

class CVSymbolSection {

    // parsing ".debug$S" sections

   // private static final String[] languageStrings = { "C", "C++", "Fortran", "masm", "Pascal", "Basic", "COBOL", "LINK", "CVTRES", "CVTPGT", "C#", "VisualBasic", "ILASM", "Java", "JScript", "MSIL", "HSIL" };

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
            out.printf("  fileid:0x%04x path=0x%x cb=%d chkType=%d checksum=[", filePos, fileId, cb, checksumType);
            for (byte b : checksum) {
                out.printf("%02x", ((int) (b) & 0xff));
            }
            out.println("] " + fileName);
            /*
            try {
                String md5 = calculateMD5Sum(filename);
                out.println("calculated=" + md5);
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
            if (fileName != null) {
                out.printf("  line: 0x%04x:%d addr=0x%08x isStatement=%-5s deltaEnd=0x%08x %s\n", fileId, lineNo, addr, isStatement, deltaEnd, fileName);
            } else {
                out.printf("  line: 0x%04x:%d addr=0x%08x isStatement=%-5s deltaEnd=0x%08x\n", fileId, lineNo, addr, isStatement, deltaEnd);
            }
        }
    }

    static class StringInfo {
        private long offset = 0;
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
    private final Vector<LineInfo> lines;
    private final HashMap<String, String> env;

    CVSymbolSection(HashMap<Integer, FileInfo> sourceFiles, HashMap<Integer, StringInfo> stringTable, Vector<LineInfo> lines, HashMap<String,String> env) {
        this.sourceFiles = sourceFiles;
        this.stringTable = stringTable;
        this.lines = lines;
        this.env = env;
    }

    void dump(PrintStream out) {
        out.println("CV sourcefiles:");
        for (final FileInfo fi : sourceFiles.values()) {
            StringInfo si = stringTable.get(fi.getFileId());
            if (si != null) {
                fi.setFileName(si.getString());
            } else {
                System.err.println("****** invalid fileid on file" + fi.toString());
            }
            fi.dump(out);
        }
        out.println("CV Strings");
        for (final StringInfo si : stringTable.values()) {
            out.printf("  0x%04x: \"%s\"\n", si.getOffset(), si.getString());
        }
        if (!env.isEmpty()) {
            out.println("CV env strings:");
            for (Map.Entry<String, String> entry : env.entrySet()) {
                out.printf("  %-4s: \"%s\"\n", entry.getKey(), entry.getValue());
            }
        }
        if (!lines.isEmpty()) {
            out.println("CV lines:");
            for (final LineInfo line : lines) {
                FileInfo fi = sourceFiles.get(line.getFileId());
                if (fi != null) {
                    line.setFileName(fi.getFileName());
                } else {
                    System.err.println("****** invalid fileid on line" + line.toString());
                }
                line.dump(out);
            }
        }
    }

}
