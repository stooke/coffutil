package com.redhat.coffutil.pecoff;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

class PESymbol {

    static final int SYM_SIZE = 18;
    private String      name;           /* Symbol Name */
    private long        value;          /* Value of Symbol */
    private int         section;        /* Section Number */
    //private int         type;           /* Symbol Type */
    private int         storageclass;   /* Storage Class */
    int         numaux;         /* Auxiliary Count */
    private int complexType;
    private int baseType;
    private int index;          // Symbol index (calculated)

   // private static final int IMAGE_SYM_DTYPE_NULL = 0;
   // private static final int IMAGE_SYM_DTYPE_POINTER = 1;
    private static final int IMAGE_SYM_DTYPE_FUNCTION = 2;
  //  private static final int IMAGE_SYM_DTYPE_ARRAY = 3;

    private static final int IMAGE_SYM_CLASS_NULL = 0;
    private static final int IMAGE_SYM_CLASS_AUTOMATIC = 1;
    private static final int IMAGE_SYM_CLASS_EXTERNAL = 2;
    private static final int IMAGE_SYM_CLASS_STATIC = 3;
    private static final int IMAGE_SYM_CLASS_EXTERNAL_DEF = 5;
    private static final int IMAGE_SYM_CLASS_FUNCTION = 101;
    private static final int IMAGE_SYM_CLASS_FILE = 103;
    private static final int IMAGE_SYM_CLASS_SECTION = 104;

    private ByteBuffer auxData;
    private PEHeader fileHeader;

    PESymbol(ByteBuffer in, PEHeader hdr, int index) {
        build(in, hdr, index);
    }

    private void build(ByteBuffer in, PEHeader hdr, int index) {
        name = PEStringTable.resolve(in, hdr);
        this.fileHeader = hdr;
        this.index = index;
        value = in.getInt();
        section = in.getShort();
        int type = in.getShort();
        complexType = type >> 8;
        baseType = type & 0xff;
        byte[] nn = new byte[2];
        in.get(nn);
        storageclass = nn[0];
        numaux = nn[1];
        int newpos = in.position() + numaux * SYM_SIZE;
        if (numaux > 0) {
            auxData = in.slice().asReadOnlyBuffer();
            auxData.order(ByteOrder.LITTLE_ENDIAN);

            // there is more data to skip
            // 18 bytes is the size of a symbol table entry
        }
        // skip to end of aux
        in.position(newpos);
    }

    private String storageClassToString(int sclass) {
        final String str;
        switch (sclass) {
            case IMAGE_SYM_CLASS_NULL:          str = "NULL"; break;
            case IMAGE_SYM_CLASS_AUTOMATIC:     str = "auto"; break;
            case IMAGE_SYM_CLASS_EXTERNAL:      str = "external"; break;
            case IMAGE_SYM_CLASS_STATIC:        str = "static"; break;
            case IMAGE_SYM_CLASS_EXTERNAL_DEF:  str = "extdef"; break;
            case IMAGE_SYM_CLASS_FUNCTION:      str = "function"; break;
            case IMAGE_SYM_CLASS_FILE:          str = "file"; break;
            case IMAGE_SYM_CLASS_SECTION:       str = "section"; break;
            default: str = "";
        }
        return str + "(" + sclass + ")";
    }

    private String parseAux() {
        if (numaux == 0 || auxData == null) {
            return "";
        }
        auxData.position(0);
        final String info;
        switch (storageclass) {
            case IMAGE_SYM_CLASS_EXTERNAL: // might be a function def
                if (complexType == IMAGE_SYM_DTYPE_FUNCTION && section > 9) {
                    // is a function def
                    int bftag = auxData.getInt();
                    int size = auxData.getInt();
                    int lineNumberPtr = auxData.getInt();
                    int nextFuncPtr = auxData.getInt();
                    //int padding = in.getShort();
                    info = "IMAGE_SYM_CLASS_EXTERNAL: IMAGE_SYM_DTYPE_FUNCTION bftag=" + bftag + " size=" + size + " lineptr=" + lineNumberPtr + " nxdfn=" + nextFuncPtr;
                } else {
                    info = "??";
                }
                break;
            case IMAGE_SYM_CLASS_FUNCTION: // .bf and /ef
                if (name.equals(".bf")) {
                    /*int padding1 =*/ auxData.getInt();
                    int lineNumber = auxData.getShort();
                    /*int padding2 =*/ auxData.getShort();
                    /*int padding3 =*/ auxData.getInt();
                    int nextBfPtr = auxData.getInt();
                    //int padding4 = in.getShort();
                    info = "line=" + lineNumber + " next .bf=" + nextBfPtr;
                } else {
                    info = "??";
                }
                break;
            case IMAGE_SYM_CLASS_FILE:  // is this a filedef?
                String fn = PEStringTable.resolve(auxData, fileHeader, 18);
                info = "fn=" + fn;
                break;
            case IMAGE_SYM_CLASS_SECTION: {
                int length = auxData.getInt();
                int numReloc = auxData.getShort();
                int numLine = auxData.getShort();
                /*int checkSum =*/ auxData.getInt();
                int sectionNumber = auxData.getShort();
                byte[] b4 = new byte[4];
                auxData.get(b4);
                /*int selection = b4[0];*/
                info = "len=" + length + " numReloc=" + numReloc + " numLine=" + numLine + " sectionNumber=" + sectionNumber;
                break;
            }
            case IMAGE_SYM_CLASS_STATIC: {
                int length = auxData.getInt();
                int numReloc = auxData.getShort();
                int numLine = auxData.getShort();
                int checkSum = auxData.getInt();
                int sectionNumber = auxData.getShort();
                /*int selection =*/ auxData.get();
                info = "len=" + length + " numReloc=" + numReloc + " numLine=" + numLine + " sectionNumber=" + sectionNumber + " check=" + checkSum;
                break;
            }
            default:
                info = "";
        }
        //System.out.printf("read sym %s\n", info);
        return info;
    }

    void dump(PrintStream out) {
        String sectionStr = "";
        if ( section > 0 ) {
            sectionStr = "section=" + section;
        } else {
            if (section == 0) {
                sectionStr = "(extern)";
            } else if (section == -1) {
                sectionStr = "(constant)";
            } else if (section == -2) {
                sectionStr = "(debug)";
            }
        }
        String auxInfo = parseAux();
        out.format("  0x%04x symbol %15s %10s val=0x%08x ctype=%d btype=%d sclass=%s numaux=%d %s\n", index, name, sectionStr, value, complexType, baseType, storageClassToString(storageclass), numaux, auxInfo);
        /*if (auxData != null) {
            out.format("   aux=");
            Util.dumpHex(out, auxData, 0, numaux * SYM_SIZE);
            out.println();
        }*/
    }

    /**
     char		n_name[8];	// Symbol Name
     long		n_value;	// Value of Symbol
     short		n_scnum;	// Section Number
     unsigned short	n_type;		// Symbol Type
     char		n_sclass;	// Storage Class
     char		n_numaux;	// Auxiliary Count
     **/
    String getName() {
        return name;
    }
/*
    public long getValue() {
        return value;
    }

    public int getSection() {
        return section;
    }

    public int getType() {
        return type;
    }

    public int getStorageclass() {
        return storageclass;
    }

    public int getComplexType() {
        return complexType;
    }

    public int getBaseType() {
        return baseType;
    }
    */
}
