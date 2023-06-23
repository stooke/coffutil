package com.redhat.coffutil.ole;

import com.redhat.coffutil.ExeFile;
import com.redhat.coffutil.ExeFileBuilder;
import com.redhat.coffutil.pecoff.Util;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

import static com.redhat.coffutil.ole.OLEFile.DirectoryEntry.BYTES;
import static java.nio.charset.StandardCharsets.UTF_16LE;

public class OLEFile implements ExeFileBuilder, ExeFile {

    private static final byte[] MAGIC = {(byte)0xd0, (byte)0xcf, 0x11, (byte)0xe0, (byte)0xa1, (byte)0xb1, 0x1a, (byte)0xe1};

    private short major;
    private short minor;
    private short byteorder;
    private int sectorSize;
    private int minisectorSize;
    private int numDirectorySectors;
    private int directoryStartSector;
    private int numFATSectors;
    private int transactionNumber;
    private int ministreamMaxSize;
    private int miniFATStartSector;
    private int numMiniFATSectors;
    private int DIFATStartSector;
    private int numDIFATSectors;

    private Fat fat;
    private MiniFat miniFat;
    private DiFat diFat;
    private List<DirectoryEntry> entries;

    public static boolean isOLEFile(File file) {
        ByteBuffer in;
        try {
            in = Util.readFile(file);
        } catch (IOException e) {
            return false;
        }
        for (byte b : MAGIC) {
            if (!in.hasRemaining()) {
                return false;
            }
            if (b != in.get()) {
                return false;
            }
        }
        return true;
    }

    //public static byte[] getMAGIC() {
    //    return MAGIC;
    //}

    @Override
    public ExeFile build(File file) throws IOException {
        ByteBuffer in = Util.readFile(file);
        in.order(ByteOrder.LITTLE_ENDIAN);
        build(in);
        return this;
    }

    private void build(ByteBuffer in) {
        in.order(ByteOrder.LITTLE_ENDIAN);
        /* skip past magic (8 bytes) (must be MAGIC) and header CLSID (must be 0) (16 bytes) */
        int pos = 8 + 16;
        in.position(pos);
        minor = in.getShort();
        major = in.getShort();
        assert major == 3 || major == 4;
        assert minor == 0x3e;
        byteorder = in.getShort();
        assert byteorder == (short) 0xfffe;
        short sectorShift = in.getShort();
        assert sectorShift == (major == 3 ? 0x9 : 0xc);
        sectorSize = 1 << sectorShift;
        short minisectorShift = in.getShort();
        assert minisectorShift == 0x6;
        minisectorSize = 1 << minisectorShift;
        pos = in.position() + 6; /* skip past reserved (all zeros) */
        in.position(pos);
        numDirectorySectors = in.getInt();
        assert (numDirectorySectors == 0 && major == 3) || major == 4;
        numFATSectors = in.getInt();
        directoryStartSector = in.getInt();
        transactionNumber = in.getInt();
        ministreamMaxSize = in.getInt();
        miniFATStartSector = in.getInt();
        numMiniFATSectors = in.getInt();
        DIFATStartSector = in.getInt();
        numDIFATSectors = in.getInt();
        assert ministreamMaxSize == 0x1000;
        dump(System.out);
        diFat = new DiFat().build(in);
        fat = new Fat().build(in); /* needs the DIFAT */
        entries = readDirectory(in); /* needs the FAT */
        miniFat = new MiniFat().build(in); /* needs the FAT and the root directory entry */
        /* dump out the source directory paths */
        entries.stream().filter(entry -> entry.name.equals("DebuggerFindSource") ).forEach(entry -> {
            System.out.format("src: %s\n", entry);
            byte[] data = entry.getData(in);
            ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
            b.position(Integer.BYTES * 2);
            int count = b.getInt();
            String[] dirs = new String[count];
            for (int i=0; i<count; i++) {
                int length = b.getInt() / 2;
                StringBuilder s = new StringBuilder();
                for (int j=0; j < length; j++) {
                    char c = b.getChar();
                    s.append(c);
                }
                dirs[i] = s.toString();
            }
            for (int i=0; i<dirs.length; i++) {
                System.out.format("directory %s\n", dirs[0]);
            }
        } );
    }

    private byte[] getStream(ByteBuffer in, int startingSector, int streamSize) {
        if (streamSize <= ministreamMaxSize && miniFat.miniStream.length > 0) {
            return miniFat.getSmallStream(startingSector, streamSize);
        } else {
            return fat.getLargeStream(in, startingSector, streamSize);
        }
    }

    private int sectorToOffset(int sectorNumber) {
        return (sectorNumber + 1) * sectorSize;
    }

    class Fat {

        static final int ENDOFCHAIN = 0xfffffffe;
        //static final int FREESECT = 0xffffffff;
        //static final int FATSECT = 0xfffffffd;
        //static final int DIFSECT = 0xfffffffc;

        private int[] sectorMap;

        int next(int start) {
            return sectorMap[start];
        }

        List<Integer> chain(int start) {
            ArrayList<Integer> c = new ArrayList<>();
            int n = sectorMap[start];
            c.add(start);
            while (n > 0) {
                c.add(n);
                n = sectorMap[n];
            }
            assert n == ENDOFCHAIN;
            return c;
        }

/**
        int find(int n) {
            for (int i = 0; i< sectorMap.length; i++) {
                if (sectorMap[i] == n) {
                    return i;
                }
            }
            return -1;
        }

        void back() {
            int nchain = 0;
            for (int i = 0; i< sectorMap.length; i++) {
                if (sectorMap[i] == ENDOFCHAIN) {
                    nchain++;
                    System.out.format("chain %2d 0x%04x:\n", nchain, i);
                    for (int j=find(i); j >= 0; j = find(j)) {
                        System.out.format("  0x%04x\n", j);
                    }
                }
            }
        }**/

        Fat build(ByteBuffer in) {
            sectorMap = new int[numFATSectors * sectorSize];
            for (int i = 0; i < numFATSectors; i++) {
                in.position(diFat.getOffsetForFatSector(i));
                for (int j = 0; j < sectorSize; j++) {
                    sectorMap[i * sectorSize + j] = in.getInt();
                }
            }
            return this;
        }

        byte[] getLargeStream(ByteBuffer in, int startingSector, long streamSize) {
            byte[] data = new byte[(int) streamSize];
            byte[] filedata = in.array();
            int nSectors = (int) streamSize / sectorSize;
            int currentSector = startingSector;
            //List<Integer> chain = chain(startingSector);
            int remainder = (int) streamSize % sectorSize;
            for (int i = 0; i < nSectors; i++) {
                System.arraycopy(filedata, sectorToOffset(currentSector), data, i * sectorSize, sectorSize);
                currentSector = next(currentSector);
            }
            if (remainder != 0) {
                System.arraycopy(filedata, sectorToOffset(currentSector), data, nSectors * sectorSize, remainder);
            }
            return data;
        }
    }

    class MiniFat {

        static final int ENDOFCHAIN = 0xfffffffe;
        //static final int FREESECT = 0xffffffff;

        private int[] sectorMap;
        private byte[] miniStream;

        MiniFat build(ByteBuffer in) {
            if (miniFATStartSector == ENDOFCHAIN) {
                sectorMap = new int[0];
                miniStream = new byte[0];
            } else {
                byte[] fatData = fat.getLargeStream(in, miniFATStartSector, numMiniFATSectors * sectorSize);
                sectorMap = new int[numMiniFATSectors * sectorSize / Integer.BYTES];
                ByteBuffer.wrap(fatData).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(sectorMap);
                DirectoryEntry entry0 = entries.get(0); /* root stream */
                assert entry0.name.equals("Root Entry");
                miniStream = fat.getLargeStream(in, entry0.startingSector, (int) entry0.streamSize);
            }
            return this;
        }

        int next(int start) {
            return sectorMap[start];
        }
/**
        List<Integer> chain(int start) {
            ArrayList<Integer> c = new ArrayList<>();
            int n = sectorMap[start];
            c.add(start);
            while (n > 0) {
                c.add(n);
                n = sectorMap[n];
            }
            assert n == ENDOFCHAIN;
            return c;
        }

        int find(int n) {
            for (int i=0; i<sectorMap.length; i++) {
                if (sectorMap[i] == n) {
                    return i;
                }
            }
            return -1;
        }

        void back() {
            int nchain = 0;
            for (int i=0; i<sectorMap.length; i++) {
                if (sectorMap[i] == ENDOFCHAIN) {
                    nchain++;
                    System.out.format("chain %2d 0x%04x:\n", nchain, i);
                    for (int j=find(i); j >= 0; j = find(j)) {
                        System.out.format("  0x%04x\n", j);
                    }
                }
            }
        }
**/

        int miniSectorToOffset(int sector) {
            return sector * minisectorSize;
        }

        byte[] getSmallStream(int startingSector, int streamSize) {
            byte[] data = new byte[streamSize];
            int nSectors = streamSize / minisectorSize;
            int currentSector = startingSector;
            //List<Integer> chain = miniFat.chain(startingSector);
            int remainder = streamSize % minisectorSize;
            for (int i = 0; i < nSectors; i++) {
                System.arraycopy(miniStream, miniSectorToOffset(currentSector), data, i * minisectorSize, minisectorSize);
                currentSector = miniFat.next(currentSector);
            }
            if (remainder != 0) {
                System.arraycopy(miniStream, miniSectorToOffset(currentSector), data, nSectors * minisectorSize, remainder);
            }
            return data;
        }

    }

    class DiFat {

        static final int INITIAL_SIZE = 109;
        int[] difat;

        int getOffsetForFatSector(int n) {
            return sectorToOffset(difat[n]);
        }

        DiFat build(ByteBuffer in) {
            difat = new int[INITIAL_SIZE + numDIFATSectors * sectorSize];
            for (int i = 0; i < INITIAL_SIZE; i++) {
                difat[i] = in.getInt();
            }
            assert in.position() == sectorSize;
            if (numDIFATSectors != 0) {
                int numEntries = numDIFATSectors * sectorSize - 1;
                in.position(sectorToOffset(DIFATStartSector));
                int idx = 0;
                for (int d = 0; d < numDIFATSectors; d++) {
                    for (int i = 0; i < numEntries; i++) {
                        difat[idx++] = in.getInt();
                    }
                    // last int in each sector is the next sector for the diFAT
                    in.position(sectorToOffset(in.getInt()));
                }
            }
            return this;
        }
    }

    @Override
    public void dump(PrintStream out) {
        out.format("%s:\n", this);
    }

    @Override
    public String toString() {
        return String.format("ole(%d.%d tx=%d bo=%d ssize=%d msize=%d ndirsect=%d dss=%d nfatsect=%d nmfatsect=%d mfatss=%d ndifat=%d difatss=%d)",
                major, minor, transactionNumber, byteorder, sectorSize, minisectorSize, numDirectorySectors, directoryStartSector, numFATSectors, numMiniFATSectors, miniFATStartSector, numDIFATSectors, DIFATStartSector);
    }

    private List<DirectoryEntry> readDirectory(ByteBuffer in) {
        List<Integer> chain = fat.chain(directoryStartSector);
        int entriesPerSector = sectorSize / BYTES;
        int numEntries = (major == 3 ? chain.size() : numDirectorySectors) * entriesPerSector;
        ArrayList<DirectoryEntry> entries = new ArrayList<>(numEntries);
        for (Integer integer : chain) {
            in.position(sectorToOffset(integer));
            for (int j = 0; j < entriesPerSector; j++) {
                DirectoryEntry entry = new DirectoryEntry(entries.size()).build(in);
                if (entry.getStreamId() == DirectoryEntry.NOSTREAM) {
                    break;
                }
                entries.add(entry);
                System.out.format("  %s\n", entry);
            }
        }
        return entries;
    }

    class DirectoryEntry {

        static final int BYTES = 128;
        static final int NAME_SIZE = 64;

        static final int NOSTREAM = 0xffffffff;
        static final int MAXREGSID = 0xfffffffa;

        String name;
        int streamId;
        /* 0=unknown/unallocated 1=storage object 2=stream object 5=root storage object */
        int type;
        /* 0=red 1=black */
        int colour;
        int leftSibling;
        int rightSibling;
        int child;
        byte[] clsid;
        int state;
        long creationTime;
        long modifiedTime;
        int startingSector;
        long streamSize;

        DirectoryEntry(int id) {
            this.streamId = id;
            assert id < MAXREGSID;
        }

        DirectoryEntry build(ByteBuffer in) {
            int startPos = in.position();
            byte[] nameBytes = new byte[NAME_SIZE];
            in.get(nameBytes);
            name = new String(nameBytes, UTF_16LE).trim();
            in.position(startPos + 64); /* past UTF-16 null-terminated name */
            short nameLength = in.getShort();
            if (nameLength == 0) {
                streamId = NOSTREAM;
                //return;
            }
            /* namelength is in bytes and includes trailing null (2 bytes in utf-16) */
            assert (name.length() * 2 + 2) == nameLength;
            type = in.get();
            colour = in.get();
            leftSibling = in.getInt();
            rightSibling = in.getInt();
            child = in.getInt();
            clsid = new byte[16];
            in.get(clsid);
            state = in.getInt();
            creationTime = in.getLong();
            modifiedTime = in.getLong();
            startingSector = in.getInt();
            streamSize = in.getLong();
            return this;
        }

        byte[] getData(ByteBuffer in) {
            assert type == 2; /* must be stream type */
            return getStream(in, startingSector, (int) streamSize);
        }

        int getStreamId() {
            return streamId;
        }

        @Override
        public String toString() {
            return String.format("entry(%s id=%d l=%d r=%d c=%d type=%d state=%d colour=%d start=0x%x(0x%x) size=%d)",
                    name, streamId, leftSibling, rightSibling, child, type, state, colour, startingSector, startingSector * sectorSize, streamSize);
        }
    }
}
