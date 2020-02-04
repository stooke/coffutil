package com.redhat.coffutil.pecoff;

import java.nio.ByteBuffer;

public class PEStringTable {

    static final int SHORT_LENGTH = 8;

    private PEStringTable() {
    }

    private static String readNullTerminatedUTF8(ByteBuffer in) {
        int oldpos = in.position();
        while (in.hasRemaining() && in.get() != 0)
            ;
        int length = in.position() - oldpos;
        byte[] sb = new byte[length];
        in.position(oldpos);
        in.get(sb);
        return new String(sb);
    }

    static String resolve(ByteBuffer in, PEFileHeader hdr) {
        return resolve(in, hdr, SHORT_LENGTH);
    }

    private static int parseInt(byte[] str, int start) {
        int idx = start;
        int i = 0;
        while (idx < str.length) {
            if (str[idx] == 0) {
                break;
            }
            i = i * 10 + str[idx++] - '0';
        }
        return i;
    }

    static String resolve(ByteBuffer in, PEFileHeader hdr, int length) {
        byte[] rawName = new byte[length];
        in.get(rawName);
        if (rawName[0] != 0 && rawName[0]!= '/'){
            return new String(rawName).trim();
        } else {
            // it's a long name; must get from the symbol table
            int oldposition = in.position();
            in.position(oldposition - length + 4);
            int offset = rawName[0] != '/' ? in.getInt() : parseInt(rawName, 1);
            int stringTableOffset = hdr.getSymPtr() + hdr.getNumSymbols() * PESymbol.SYM_SIZE;
            in.position(stringTableOffset + offset);
            String longname = readNullTerminatedUTF8(in);
            in.position(oldposition);
            return longname.trim();
        }
    }

    public static String getString0(ByteBuffer in, int maxlen) {
        byte[] buf = new byte[maxlen];
        int len = 0;
        while (maxlen-- > 0) {
            byte b = in.get();
            if (b == 0) {
                break;
            }
            buf[len++] = b;
        }
        return new String(buf, 0, len);
    }

    static String getNString(ByteBuffer in, int mlen) {
        int maxlen = in.getShort();
        byte[] buf = new byte[maxlen];
        int len = 0;
        while (maxlen-- > 0) {
            byte b = in.get();
            if (b == 0) {
                break;
            }
            buf[len++] = b;
        }
        return new String(buf, 0, len);
    }

}