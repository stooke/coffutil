package com.redhat.coffutil.coff;

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
        String filename;
        byte[] checksum;
        int fileid;
        int cb;
        int checksumType;

        FileInfo(int fileid, int cb, int checksumType, byte[] checksum) {
            this.fileid = fileid;
            this.cb = cb;
            this.checksumType = checksumType;
            this.checksum = checksum;
        }

        void dump(PrintStream out) {
            out.printf("  fileid:%d cb=%d chkType=%d checksum=[", fileid, cb, checksumType);
            for (byte b : checksum) {
                out.printf("%02x", ((int) (b) & 0xff));
            }
            out.println("] " + filename);
            /**
            try {
                String md5 = calculateMD5Sum(filename);
                out.println("calculated=" + md5);
            } catch (Exception e) {
                e.printStackTrace();
            }**/
        }

        public String calculateMD5Sum(String fn) throws NoSuchAlgorithmException, IOException
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(Files.readAllBytes(Paths.get(fn)));
            byte[] digest = md.digest();
            String md5sum = DatatypeConverter.printHexBinary(digest).toUpperCase();
            return md5sum;
        }
    }

    static class LineInfo {
        int addr;
        int lineNo;
        boolean isStatement;
        int deltaEnd;
        LineInfo(int addr, int lineNo, boolean isStatement, int deltaEnd) {
            this.addr = addr;
            this.lineNo = lineNo;
            this.isStatement = isStatement;
            this.deltaEnd = deltaEnd;
        }

        void dump(PrintStream out) {
            out.printf("  line: %4d addr=0x%08x isStatement=%-5s deltaEnd=0x%08x\n", lineNo, addr, isStatement, deltaEnd);
        }
    }

    private final Vector<FileInfo> sourceFiles;
    private final Vector<String> stringTable;
    private final Vector<LineInfo> lines;
    private final HashMap<String, String> env;

    CVSymbolSection(Vector<FileInfo> sourceFiles, Vector<String> stringTable, Vector<LineInfo> lines, HashMap<String,String> env) {
        this.sourceFiles = sourceFiles;
        this.stringTable = stringTable;
        this.lines = lines;
        this.env = env;
    }

    void dump(PrintStream out) {
        out.println("CV sourcefiles:");
        for (final FileInfo fi : sourceFiles) {
            fi.dump(out);
        }
        out.println("CV Strings");
        for (int i=0; i<stringTable.size(); i++) {
            out.printf("  %d: \"%s\"\n", i, stringTable.get(i));
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
                line.dump(out);
            }
        }
    }

}
