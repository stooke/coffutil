package com.redhat.coffutil.msf;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.pecoff.Util;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MultiStreamFile {

    private MSFSuperBlock superblock;
    private RootStream rootStream;
    private StreamDef[] streams;
    private ByteBuffer fileBuffer;

    public void build(ByteBuffer in) {
        this.fileBuffer = in;
        superblock = new MSFSuperBlock();
        superblock.build(in, 0);
        FreeBlockMap fbm1 = new FreeBlockMap();
        fbm1.build(in, superblock.blockSize);
        FreeBlockMap fbm2 = new FreeBlockMap();
        fbm2.build(in, superblock.blockSize * 2);
        rootStream = new RootStream(in);
        rootStream.build(in);
    }

    public void dump(PrintStream out) {
        out.println("superblock: " + superblock);
        rootStream.dump(out);
        for (int i=0; i<Math.min(20, streams.length); i++) {
            out.format("stream %d: ", i);
            StreamDef stream = streams[i];
            stream.dumpData(out);
        }
    }

    public ByteBuffer getStream(int i) {
        return streams[i].get(fileBuffer);
    }

    static class MSFSuperBlock {

        final static String magic = "Microsoft C/C++ MSF 7.00\r\n\u001aDS\u0000\u0000\u0000";
        int blockSize;
        int freeBlockMapBlock;
        int numBlocks;
        int numDirectoryBytes; /* root stream size */
        int unknown;
        int blockMapAddr;  /* root stream page number list */

        int build(ByteBuffer in, int pos) {
            //CoffUtilContext.instance().debug(Util.dumpHex(in, pos, magic.length()));
            in.position(pos + magic.length());
            blockSize = in.getInt();
            freeBlockMapBlock = in.getInt();
            numBlocks = in.getInt();
            numDirectoryBytes = in.getInt();  /* root stream size */
            unknown = in.getInt();
            blockMapAddr = in.getInt();  /* root stream page number list */
            return in.position();
        }

        @Override
        public String toString() {
            return String.format("msfsuper(bs=%d fbm=%d nb=%d bmapaddr=0x%x dirBytes=%d", blockSize, freeBlockMapBlock, numBlocks, blockMapAddr, numDirectoryBytes);
        }
    }

    class FreeBlockMap {

        byte[] blocks;

        FreeBlockMap() {
            blocks = new byte[superblock.blockSize];
        }

        int build(ByteBuffer in, int pos) {
            in.position(pos);
            in.get(blocks);
            return in.position();
        }
    }

    class StreamDef {

        int streamsize;
        int[] pageList;
        byte[] bytes;

        StreamDef(ByteBuffer in, int streamsize, int pos) {
            in.position(pos);
            this.streamsize = streamsize;
            pageList = new int[(streamsize +  superblock.blockSize - 1)/ superblock.blockSize];
            for (int i=0; i<pageList.length; i++) {
                pageList[i] = in.getInt();
            }
        }

        StreamDef(int streamsize, int[] pageList) {
            this.streamsize = streamsize;
            this.pageList = pageList;
        }

        /* read pagelist */

        protected ByteBuffer get(ByteBuffer in) {
            if (bytes == null) {
                int bs = superblock.blockSize;
                byte[] inbytes = in.array(); /* this fails for a readonly buffer */
                bytes = new byte[streamsize];
                int numPages = streamsize / bs;  /* round down to get cound of whole blocks */
                /* read full pages first */
                for (int i = 0; i < numPages; i++) {
                    int srcPos = pageList[i] * bs;
                    System.arraycopy(inbytes, srcPos, bytes, i * bs, bs);
                }
                /* read remainder partial block */
                int remainder = streamsize % bs;
                if (remainder != 0) {
                    int srcPos = pageList[numPages] * bs;
                    System.arraycopy(inbytes, srcPos, bytes, numPages * bs, remainder);
                }
            }
            return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        }

        public ByteBuffer get() {
            return get(fileBuffer);
        }

        @Override
        public String toString() {
            return String.format("msfstream(streamsize=%d npages=%d start=0x%x)", streamsize, pageList.length, pageList.length > 0 ? pageList[0] * superblock.blockSize : 0);
        }

        void dump(PrintStream out) {
            out.print(" " + this + " [");
            for (int i=0; i<pageList.length; i++) {
                if (i < 10) {
                    out.format("0x%x ", pageList[i] * superblock.blockSize);
                } else {
                    out.print("...");
                    break;
                }
            }
            out.println("]");
        }

        void dumpData(PrintStream out) {
            out.format(" %s [%s]\n", this, Util.dumpHex(get(), 0, Math.min(16, bytes.length)));
        }
    }

    class RootStream extends StreamDef {

        RootStream(ByteBuffer in) {
            super(in, superblock.numDirectoryBytes, superblock.blockMapAddr * superblock.blockSize);
        }

        int build(ByteBuffer in) {
            ByteBuffer buffer = get(in);
            buffer.position(0);
            int n = buffer.getInt();
            CoffUtilContext.getInstance().debug("Numsteams = %s\n");
            streams = new StreamDef[n + 1]; /* + 1 to leave room for this stream, the root stream */
            streams[0] = this;
            int sizePos = buffer.position();
            int plPos = buffer.position() + Integer.BYTES * n;
            for (int i=0; i < n; i++) {
                int size = buffer.getInt(sizePos + Integer.BYTES * i);
                StreamDef stream = new StreamDef(buffer, size, plPos);
                int np = (size + superblock.blockSize - 1) / superblock.blockSize;
                plPos = plPos + Integer.BYTES * np;
                streams[i + 1] = stream;
            }
            return plPos;
        }

        @Override
        public String toString() {
            return String.format("rootstream(streamsize=%d npages=%d nstream=%d)", streamsize, pageList.length, streams.length);
        }

        void dump(PrintStream out) {
            out.format("root: %d streams:\n", streams.length);
            int max = 10;
            int min = 1;
            for (StreamDef stream : streams) {
                if (max-- < 0) break;
                if (min-- > 0) continue;
                stream.dump(out);
            }
        }
    }
}
