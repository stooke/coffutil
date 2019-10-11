package com.redhat.coffutil.coff;

import java.nio.ByteBuffer;

class PEStringTable {

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

    static String resolve(ByteBuffer in, PEHeader hdr) {
        return resolve(in, hdr, SHORT_LENGTH);
    }

    static String resolve(ByteBuffer in, PEHeader hdr, int length) {
        byte[] rawName = new byte[length];
        in.get(rawName);
        if (rawName[0] != 0){
            return new String(rawName).trim();
        } else {
            // it's a long name; must get from the symbol table
            int oldposition = in.position();
            in.position(oldposition - length + 4);
            int offset = in.getInt();
            int stringTableOffset = hdr.getSymPtr() + hdr.getNumSymbols() * PESymbol.SYM_SIZE;
            in.position(stringTableOffset + offset);
            String longname = readNullTerminatedUTF8(in);
            in.position(oldposition);
            return longname.trim();
        }
    }

    static String getString0(ByteBuffer in, int maxlen) {
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