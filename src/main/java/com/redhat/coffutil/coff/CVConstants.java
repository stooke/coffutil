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

    // type table
    int T_NOTYPE       = 0x0000;
    int T_VOID         = 0x0003;
    int T_CHAR         = 0x0010; // 8 bit signed (java type)
    int T_WCHAR        = 0x0071;
    int T_CHAR16       = 0x007a; // 16 bit unicode (Java type)
    int T_SHORT        = 0x0011; // 16 bit signed int (Java type)
    int T_LONG         = 0x0014; // 32 bit signed (java type? maybe T_INT4?)
    int T_QUAD         = 0x0013; // 64 bit signed int (Java type)
    int T_REAL32       = 0x0040; // 32 bit float (Java type)
    int T_REAL64       = 0x0041; // 64 but double (Java type)
    int T_RCHAR        = 0x0070; // ?? "really a char"

    int T_POINTER_BITS  = 0x0700;
    int T_POINTER32     = 0x0400; // 32 bit pointer
    int T_POINTER64     = 0x0600; // 64 bit pointer

    int LF_MODIFIER    = 0x1001;
    int LF_POINTER     = 0x1002;
    int LF_PROCEDURE   = 0x1008;
    int LF_ARGLIST     = 0x1201;
    int LF_ARRAY       = 0x1503;
    int LF_CLASS       = 0x1504;
    int LF_ENUM        = 0x1507;
    int LF_TYPESERVER2 = 0x1515;

    int LF_CHAR        = 0x8000;
    int LF_SHORT       = 0x8001;
    int LF_USHORT      = 0x8002;
    int LF_LONG        = 0x8003;
    int LF_ULONG       = 0x8004;
    int LF_REAL32      = 0x8005;
    int LF_REAL64      = 0x8006;
    int LF_QUADWORD    = 0x8009;
    int LF_UQUADWORD   = 0x800a;
    int LF_OCTWORD     = 0x8017;
    int LF_UOCTWORD    = 0x8018;
}
