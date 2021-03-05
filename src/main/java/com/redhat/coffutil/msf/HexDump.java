package com.redhat.coffutil.msf;

import java.nio.ByteBuffer;

public class HexDump {

    /* ADDRESS_LENGTH - number of characters in address. */
    private static final int ADDRESS_LENGTH = 6;

    private static final char[] hex = { '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /* This section is format - specific. */
    private static final int LINELENGTH = 16;

    // offset - offset added to all displayed addresses
    // allows a buffer of 256 to pretend to be in the middle of a huge file
    // must always be a multiple of 16 for now
    private long displayAddrOffset = 0;

    public String makeLines(ByteBuffer data, long displayAddrOffset, long start, long length) {
        this.displayAddrOffset = displayAddrOffset;
        StringBuilder sb = new StringBuilder();
        long end = start + length;
        while (start < end) {
            start = makeLine(sb, data, start, length);
            sb.append("\n");
        }
        return sb.toString();
    }

    private long makeLine(StringBuilder sb, ByteBuffer data, long start, long length) {
        /* Format aaaa bbbbbbbb bbbbbbbb  bbbbbbbb bbbbbbbb  ........ ........ */
        final long end = start + length;
        final long lineStart = start - (start % LINELENGTH);
        if (lineStart >= length) {
            return end;
        }
        final long lineEnd = Math.min(end, lineStart + LINELENGTH);

        // write address
        final long so = lineStart + displayAddrOffset;
        for (int i = ADDRESS_LENGTH * 4 - 4; i > 0; i -= 4) {
            toHexNybble(sb, (int) (so >> i));
        }
        sb.append("0 ");

        // slower version is (works for LINELENGTH!=16)
        //for ( int i=addressLength*4-4; i>=0; i-=4 )
        //    toHexNybble( (int)(so>>i) );
        //emit( ' ' );

        /* Write bytes in hex. */
        for (int i = 0; i < LINELENGTH; i++) {
            if (((lineStart + i) < start) || ((lineStart + i) >= length))
                sb.append("  ");
            else
                toHexByte(sb, data.get((int)(lineStart + i)));
            if (i % 4 == 3)
                sb.append(' ');
            if (i % 8 == 7)
                sb.append(' ');
        }

        // write bytes in text
        for (int i = 0; i < LINELENGTH; i++) {
            if (((lineStart + i) < start) || ((lineStart + i) >= length))
                sb.append(' ');
            else {
                byte b = data.get((int)(lineStart + i));
                char c = (char)(b);
                if (b < 32 || b == 0x7f)
                    c = '.';
                sb.append(c);
            }
            if (i % 8 == 7)
                sb.append(' ');
        }
        return lineEnd;
    }

    private void toHexByte(StringBuilder sb, int i) {
        sb.append(hex[(i >> 4) & 0xf]);
        sb.append(hex[i & 0xf]);
    }
    /*
    private void toHexInt(StringBuilder sb, int i) {
        toHexShort(sb, i >> 16);
        toHexShort(sb, i);
    }
    private void toHexLong(StringBuilder sb, long l) {
        toHexInt(sb, (int)(l >> 32) );
        toHexInt(sb, (int)(l) );
    }
    private void toHexLong6(StringBuilder sb, long l) {
        toHexShort(sb, (int)(l >> 32) );
        toHexInt(sb, (int)(l));
    }
    private void toHexShort(StringBuilder sb, int i) {
        toHexByte(sb,i >> 8);
        toHexByte(sb, i);
    }
    */
    private void toHexNybble(StringBuilder sb, int i) {
        sb.append(hex[i & 0xf]);
    }

}
