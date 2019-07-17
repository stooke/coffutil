package com.redhat.coffutil;


import java.io.PrintStream;
import java.nio.ByteBuffer;

class PESymbol {

    static final int SYM_SIZE = 18;
    /**
     char		n_name[8];	// Symbol Name
     long		n_value;	// Value of Symbol
     short		n_scnum;	// Section Number
     unsigned short	n_type;		// Symbol Type
     char		n_sclass;	// Storage Class
     char		n_numaux;	// Auxiliary Count
     **/
    private String      name;           /* Symbol Name */
    private long        value;          /* Value of Symbol */
    private int         section;        /* Section Number */
    private int         type;           /* Symbol Type */
    private int         storageclass;   /* Storage Class */
    int         numaux;         /* Auxiliary Count */
    private int complexType;
    private int baseType;

    private static final int IMAGE_SYM_DTYPE_NULL = 0;
    private static final int IMAGE_SYM_DTYPE_POINTER = 1;
    private static final int IMAGE_SYM_DTYPE_FUNCTION = 2;
    private static final int IMAGE_SYM_DTYPE_ARRAY = 3;

    private static final int IMAGE_SYM_CLASS_NULL = 0;
    private static final int IMAGE_SYM_CLASS_AUTOMATIC = 1;
    private static final int IMAGE_SYM_CLASS_EXTERNAL = 2;
    private static final int IMAGE_SYM_CLASS_STATIC = 3;
    private static final int IMAGE_SYM_CLASS_EXTERNAL_DEF = 5;
    private static final int IMAGE_SYM_CLASS_FUNCTION = 101;
    private static final int IMAGE_SYM_CLASS_FILE = 103;
    private static final int IMAGE_SYM_CLASS_SECTION = 104;


    PESymbol[] aux;

    PESymbol(ByteBuffer in, PEHeader hdr) {
        name = PEStringTable.resolve(in, hdr);
        value = in.getInt();
        section = in.getShort();
        type = in.getShort();
        complexType = type >> 8;
        baseType = type & 0xff;
        byte[] nn = new byte[2];
        in.get(nn);
        storageclass = nn[0];
        numaux = nn[1];
        if (numaux > 0) {
            aux = new PESymbol[numaux];

            // there is more data to skip
            // 18 bytes is the size of a symbol table entry
            int newpos = in.position() + numaux * SYM_SIZE;

            switch (storageclass) {
                case IMAGE_SYM_CLASS_EXTERNAL: // might be a function def
                    if (complexType == IMAGE_SYM_DTYPE_FUNCTION && section > 9) {
                        // is a function def
                        int bftag = in.getInt();
                        int size = in.getInt();
                        int lineNumberPtr = in.getInt();
                        int nextFuncPtr = in.getInt();
                        //int padding = in.getShort();
                    }
                    break;
                case IMAGE_SYM_CLASS_FUNCTION: // .bf and /ef
                    if (name.equals(".bf")) {
                        int padding1 = in.getInt();
                        int lineNumber = in.getShort();
                        int padding2 = in.getShort();
                        int padding3 = in.getInt();
                        int nextBfPtr = in.getInt();
                        //int padding4 = in.getShort();
                    }
                    break;
                case IMAGE_SYM_CLASS_FILE:  // is this a filedef?
                    String fn = PEStringTable.resolve(in, hdr, 18);
                    break;
                case IMAGE_SYM_CLASS_SECTION:
                    int length = in.getInt();
                    int numReloc = in.getShort();
                    int numLine = in.getShort();
                    int checkSum = in.getInt();
                    int sectionNumber = in.getShort();
                    byte[] b4 = new byte[4];
                    in.get(b4);
                    int selection = b4[0];
                    break;
            }

            // skip to end of auc
            in.position(newpos);
        }
    }

    void dump(PrintStream out) {
        out.print("  symbol " + name + " val=" + value);
        if ( section > 0 ) {
            out.print(" section=" + section);
        } else {
            String sectionStr = "";
            if (section == 0) {
                sectionStr = "(extern)";
            } else if (section == -1) {
                sectionStr = "(constant)";
            } else if (section == -2) {
                sectionStr = "(debug)";
            }
            out.print(" " + sectionStr);
        }
        out.println(" ctype=" + complexType + " btype=" + baseType + " class=" + storageclass + " numaux=" + numaux);
    }
}
