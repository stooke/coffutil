package com.redhat.coffutil.msf;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.ExeFileBuilder;
import com.redhat.coffutil.pecoff.Util;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MultiStreamFile implements ExeFileBuilder, ExeFile {

    private MSFSuperBlock superblock;
    private RootStream rootStream;
    private StreamDef[] streams;
    private ByteBuffer fileBuffer;

    @Override
    public ExeFile build(File file) throws IOException {
        ByteBuffer in = Util.readFile(file);
        in.order(ByteOrder.LITTLE_ENDIAN);
        build(in);
        return this;
    }

    public void build(ByteBuffer in) {
        this.fileBuffer = in;
        superblock = new MSFSuperBlock();
        superblock.build(in, 0);
        /* TODO - may need to skip to free page map location instead of assuming it's sequential. */
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
        for (int i=0; i < Math.min(1999, streams.length); i++) {
            out.format("stream %d: ", i);
            StreamDef stream = streams[i];
            stream.dumpDataSmall(out);
        }
    }

    public ByteBuffer getStreamBuffer(int i) {
        return streams[i].get(fileBuffer);
    }

    public StreamDef getStream(int i) {
        return streams[i];
    }

    public int streamCount() {
        return streams.length;
    }

    static class MSFSuperBlock {

        final static String magic = "Microsoft C/C++ MSF 7.00\r\n\u001aDS\u0000\u0000\u0000";
        int blockSize;
        int freeBlockMapPage;
        int numBlocks;
        int numDirectoryBytes; /* root stream size */
        int unknown;
        int blockMapPage;  /* root stream page number list */

        int build(ByteBuffer in, int pos) {
            //CoffUtilContext.instance().debug(Util.dumpHex(in, pos, magic.length()));
            // some implementations take 'magic' from byte 0 to the first EOF + "DS" + NULL
            //   (0x1a 0x44 0x53 0x00 + padding until next DWORD)
            in.position(pos + magic.length());
            blockSize = in.getInt();
            freeBlockMapPage = in.getInt();
            numBlocks = in.getInt();
            numDirectoryBytes = in.getInt();  /* root stream size */
            unknown = in.getInt();
            blockMapPage = in.getInt();  /* root stream page number list */
            return in.position();
        }

        @Override
        public String toString() {
            return String.format("msfsuper(pageSize=%d numPages=%d dirBytes=%d freePageMap=0x%x blockMap=0x%x", blockSize, numBlocks, numDirectoryBytes, freeBlockMapPage, blockMapPage);
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

    public class StreamDef {

        int streamsize;
        int[] pageList;
        byte[] bytes;

        StreamDef(ByteBuffer in, int streamsize, int pos) {
            in.position(pos);
            this.streamsize = streamsize;
            pageList = new int[(streamsize +  superblock.blockSize - 1)/ superblock.blockSize];
            for (int i = 0; i < pageList.length; i++) {
                pageList[i] = in.getInt();
            }
        }

        StreamDef(int streamsize, int[] pageList) {
            this.streamsize = streamsize;
            this.pageList = pageList;
        }

        public int length() {
            return streamsize;
        }

        /* read pagelist */

        protected ByteBuffer get(ByteBuffer in) {
            if (bytes == null) {
                if (streamsize < 0) {
                    bytes = new byte[0];
                    return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
                }
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

        public void dump(PrintStream out) {
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

        public void dumpData(PrintStream out) {
            String s = new HexDump().makeLines(get(), 0, 0, streamsize);
            out.print(s);
        }

        private void dumpDataSmall(PrintStream out) {
            out.format(" %s [%s]\n", this, Util.dumpHex(get(), 0, Math.min(16, bytes.length)));
        }
    }

    class RootStream extends StreamDef {

        RootStream(ByteBuffer in) {
            super(in, superblock.numDirectoryBytes, superblock.blockMapPage * superblock.blockSize);
        }

        int build(ByteBuffer in) {
            ByteBuffer buffer = get(in);
            buffer.position(0);
            int numStreams = buffer.getInt();
            CoffUtilContext.getInstance().debug("Numsteams = %s\n", numStreams);
            streams = new StreamDef[numStreams + 1]; /* + 1 to leave room for this stream, the root stream */
            streams[0] = this;
            int sizePos = buffer.position();
            int plPos = buffer.position() + Integer.BYTES * numStreams;
            for (int i = 0; i < numStreams; i++) {
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

        public void dump(PrintStream out) {
            out.format("root: %d streams:\n", streams.length);
            int max = 19999;
            int min = 1;
            for (StreamDef stream : streams) {
                if (max-- < 0) break;
                if (min-- > 0) continue;
                stream.dump(out);
            }
        }
    }
}
