package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;

import static com.redhat.coffutil.CVConstants.CV_SIGNATURE_C13;

class CVTypeSectionBuilder {

    PrintStream out = System.out;
    private final boolean debug = true;

    CVTypeSection build(ByteBuffer in, PESectionHeader shdr) {

        final int sectionBegin = shdr.getRawDataPtr();
        final int sectionEnd = sectionBegin + shdr.getRawDataSize();
        in.position(sectionBegin);

        int symSig = in.getInt();
        if (symSig != CV_SIGNATURE_C13) {
            out.println("**** unexpected debug signature " + symSig + "; expected " + CV_SIGNATURE_C13);
        }

        if (debug) {
            out.printf("debug$T section begin=0x%x end=0x%x\n", sectionBegin, sectionEnd);
        }

        // parse symbol debug info
        while (in.position() < sectionEnd) {

            // align on 4 bytes
            while (((in.position() - sectionBegin) & 3) != 0) {
                in.get();
            }

            int startPosition = in.position();
            int len = in.getShort();

            int nextPosition = startPosition + len;
            if (nextPosition > sectionEnd) {
                break;
            }

            if (debug) {
                out.printf("debug: foffset=0x%x soffset=0x%x len=%d next=0x%x remain=%d\n", startPosition,
                        (startPosition - sectionBegin), len, (nextPosition - sectionBegin), (sectionEnd - in.position()));
            }

            int leaf = in.getShort();

            /*  for some very odd reason GUID is stored like this:
            int guid1 = in.getInt();
            int guid2 = in.getShort();
            int guid3 = in.getShort();
            byte[] guid5[10]
             */
            byte[] guid = new byte[16];
            in.get(guid);
            swap(guid, 0, 3);
            swap(guid, 1, 2);
            swap(guid, 4, 5);
            swap(guid, 6, 7);

            int age = in.getInt();
            String name = PEStringTable.getString0(in, nextPosition - in.position());

            out.printf("CV Type len=%d leaf=0x%04x age=0x%08x, GUID=[", len, leaf, age);
            for (byte b : guid) {
                out.printf("%02x", b);
            }
            out.printf("] PDB=%s\n", name);
            in.position(nextPosition);
        }

        return new CVTypeSection();
    }

    private void swap(byte[] b, int idx1, int idx2) {
        byte tmp = b[idx1];
        b[idx1] = b[idx2];
        b[idx2] = tmp;
    }

}
