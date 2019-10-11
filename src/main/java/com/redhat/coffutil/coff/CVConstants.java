package com.redhat.coffutil.coff;

public interface CVConstants {

    int CV_SIGNATURE_C13 = 4;
    int S_COMPILE   = 0x0001;
    int S_SSEARCH   = 0x0005;
    int S_END       = 0x0006;
    int S_OBJNAME   = 0x1101;
    int S_LDATA32_ST = 0x1007;
    int S_FRAMEPROC = 0x1012;
    int S_CONSTANT  = 0x1107;
    int S_UDT       = 0x1108;
    int S_LDATA32   = 0x110c;
    int S_GDATA32   = 0x110d;
    int S_GPROC32   = 0x1110;
    int S_REGREL32  = 0x1111;
    int S_COMPILE3  = 0x113c;
    int S_ENVBLOCK  = 0x113d;

    int DEBUG_S_IGNORE      = 0x00;
    int DEBUG_S_SYMBOLS     = 0xf1;
    int DEBUG_S_LINES       = 0xf2;
    int DEBUG_S_STRINGTABLE = 0xf3;
    int DEBUG_S_FILECHKSMS  = 0xf4;
}
