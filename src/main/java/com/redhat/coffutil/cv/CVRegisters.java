package com.redhat.coffutil.cv;

import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public abstract class CVRegisters {

    private static final String[] gp64Names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    private static final String[] gpNames64 = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
            "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
    private static final String[] gpNames4 = { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
    private static final String[] gpNames2 = { "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
    private static final String[] gpNames1 = { "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
    private static final String[] fpNames = { "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7" };

    /* Register definitions */

    /* 8 bit registers. */
    static final short CV_AMD64_R8B = 344;
    static final short CV_AMD64_R9B = 345;
    static final short CV_AMD64_R10B = 346;
    static final short CV_AMD64_R11B = 347;
    static final short CV_AMD64_R12B = 348;
    static final short CV_AMD64_R13B = 349;
    static final short CV_AMD64_R14B = 350;
    static final short CV_AMD64_R15B = 351;

    static final short CV_AMD64_AL = 1;
    static final short CV_AMD64_CL = 2;
    static final short CV_AMD64_DL = 3;
    static final short CV_AMD64_BL = 4;
    static final short CV_AMD64_AH = 5;
    static final short CV_AMD64_CH = 6;
    static final short CV_AMD64_DH = 7;
    static final short CV_AMD64_BH = 8;

    static final short CV_AMD64_SIL = 324;
    static final short CV_AMD64_DIL = 325;
    static final short CV_AMD64_BPL = 326;
    static final short CV_AMD64_SPL = 327;

    /* 16 bit registers. */
    static final short CV_AMD64_R8W = 352;
    static final short CV_AMD64_R9W = 353;
    static final short CV_AMD64_R10W = 354;
    static final short CV_AMD64_R11W = 355;
    static final short CV_AMD64_R12W = 356;
    static final short CV_AMD64_R13W = 357;
    static final short CV_AMD64_R14W = 358;
    static final short CV_AMD64_R15W = 359;

    static final short CV_AMD64_AX = 9;
    static final short CV_AMD64_CX = 10;
    static final short CV_AMD64_DX = 11;
    static final short CV_AMD64_BX = 12;
    static final short CV_AMD64_SP = 13;
    static final short CV_AMD64_BP = 14;
    static final short CV_AMD64_SI = 15;
    static final short CV_AMD64_DI = 16;

    /* 32 bit registers. */
    static final short CV_AMD64_R8D = 360;
    static final short CV_AMD64_R9D = 361;
    static final short CV_AMD64_R10D = 362;
    static final short CV_AMD64_R11D = 363;
    static final short CV_AMD64_R12D = 364;
    static final short CV_AMD64_R13D = 365;
    static final short CV_AMD64_R14D = 366;
    static final short CV_AMD64_R15D = 367;

    static final short CV_AMD64_EAX = 17;
    static final short CV_AMD64_ECX = 18;
    static final short CV_AMD64_EDX = 19;
    static final short CV_AMD64_EBX = 20;
    static final short CV_AMD64_ESP = 21;
    static final short CV_AMD64_EBP = 22;
    static final short CV_AMD64_ESI = 23;
    static final short CV_AMD64_EDI = 24;

    /* 64 bit registers. */
    static final short CV_AMD64_RAX = 328;
    static final short CV_AMD64_RBX = 329;
    static final short CV_AMD64_RCX = 330;
    static final short CV_AMD64_RDX = 331;
    static final short CV_AMD64_RSI = 332;
    static final short CV_AMD64_RDI = 333;
    static final short CV_AMD64_RBP = 334;
    static final short CV_AMD64_RSP = 335;

    static final short CV_AMD64_R8 = 336;
    static final short CV_AMD64_R9 = 337;
    static final short CV_AMD64_R10 = 338;
    static final short CV_AMD64_R11 = 339;
    static final short CV_AMD64_R12 = 340;
    static final short CV_AMD64_R13 = 341;
    static final short CV_AMD64_R14 = 342;
    static final short CV_AMD64_R15 = 343;

    /* FP registers. */
    static final short CV_AMD64_XMM0 = 154;
    static final short CV_AMD64_XMM1 = 155;
    static final short CV_AMD64_XMM2 = 156;
    static final short CV_AMD64_XMM3 = 157;
    static final short CV_AMD64_XMM4 = 158;
    static final short CV_AMD64_XMM5 = 159;
    static final short CV_AMD64_XMM6 = 160;
    static final short CV_AMD64_XMM7 = 161;

    static final short CV_AMD64_XMM0L = 194;
    static final short CV_AMD64_XMM1L = 195;
    static final short CV_AMD64_XMM2L = 196;
    static final short CV_AMD64_XMM3L = 197;
    static final short CV_AMD64_XMM4L = 198;
    static final short CV_AMD64_XMM5L = 199;
    static final short CV_AMD64_XMM6L = 200;
    static final short CV_AMD64_XMM7L = 201;

    static final short CV_AMD64_XMM0_0 = 162;
    static final short CV_AMD64_XMM1_0 = 166;
    static final short CV_AMD64_XMM2_0 = 170;
    static final short CV_AMD64_XMM3_0 = 174;

    private static final Map<Integer, String> regNames = new HashMap<>(200);

    private static void addReg(int regNum, String regName) {
        regNames.put(regNum, regName);
        //System.out.format("        addReg(CV_AMD64_%s, \"%s\");\n", regName.toUpperCase(), regName);
    }

    static {
        addReg(CV_AMD64_AL, "al");
        addReg(CV_AMD64_CL, "cl");
        addReg(CV_AMD64_DL, "dl");
        addReg(CV_AMD64_BL, "bl");
        addReg(CV_AMD64_AH, "ah");
        addReg(CV_AMD64_CH, "ch");
        addReg(CV_AMD64_DH, "dh");
        addReg(CV_AMD64_BH, "bh");
        addReg(CV_AMD64_AX, "ax");
        addReg(CV_AMD64_CX, "cx");
        addReg(CV_AMD64_DX, "dx");
        addReg(CV_AMD64_BX, "bx");
        addReg(CV_AMD64_SP, "sp");
        addReg(CV_AMD64_BP, "bp");
        addReg(CV_AMD64_SI, "si");
        addReg(CV_AMD64_DI, "di");
        addReg(CV_AMD64_EAX, "eax");
        addReg(CV_AMD64_ECX, "ecx");
        addReg(CV_AMD64_EDX, "edx");
        addReg(CV_AMD64_EBX, "ebx");
        addReg(CV_AMD64_ESP, "esp");
        addReg(CV_AMD64_EBP, "ebp");
        addReg(CV_AMD64_ESI, "esi");
        addReg(CV_AMD64_EDI, "edi");
        addReg(CV_AMD64_XMM0, "xmm0");
        addReg(CV_AMD64_XMM1, "xmm1");
        addReg(CV_AMD64_XMM2, "xmm2");
        addReg(CV_AMD64_XMM3, "xmm3");
        addReg(CV_AMD64_XMM4, "xmm4");
        addReg(CV_AMD64_XMM5, "xmm5");
        addReg(CV_AMD64_XMM6, "xmm6");
        addReg(CV_AMD64_XMM7, "xmm7");
        addReg(CV_AMD64_XMM0_0, "xmm0_0");
        addReg(CV_AMD64_XMM1_0, "xmm1_0");
        addReg(CV_AMD64_XMM2_0, "xmm2_0");
        addReg(CV_AMD64_XMM3_0, "xmm3_0");
        addReg(CV_AMD64_XMM0L, "xmm0l");
        addReg(CV_AMD64_XMM1L, "xmm1l");
        addReg(CV_AMD64_XMM2L, "xmm2l");
        addReg(CV_AMD64_XMM3L, "xmm3l");
        addReg(CV_AMD64_XMM4L, "xmm4l");
        addReg(CV_AMD64_XMM5L, "xmm5l");
        addReg(CV_AMD64_XMM6L, "xmm6l");
        addReg(CV_AMD64_XMM7L, "xmm7l");
        addReg(CV_AMD64_RAX, "rax");
        addReg(CV_AMD64_RBX, "rbx");
        addReg(CV_AMD64_RCX, "rcx");
        addReg(CV_AMD64_RDX, "rdx");
        addReg(CV_AMD64_RSI, "rsi");
        addReg(CV_AMD64_RDI, "rdi");
        addReg(CV_AMD64_RBP, "rbp");
        addReg(CV_AMD64_RSP, "rsp");
        addReg(CV_AMD64_R8, "r8");
        addReg(CV_AMD64_R9, "r9");
        addReg(CV_AMD64_R10, "r10");
        addReg(CV_AMD64_R11, "r11");
        addReg(CV_AMD64_R12, "r12");
        addReg(CV_AMD64_R13, "r13");
        addReg(CV_AMD64_R14, "r14");
        addReg(CV_AMD64_R15, "r15");
        addReg(CV_AMD64_R8B, "r8b");
        addReg(CV_AMD64_R9B, "r9b");
        addReg(CV_AMD64_R10B, "r10b");
        addReg(CV_AMD64_R11B, "r11b");
        addReg(CV_AMD64_R12B, "r12b");
        addReg(CV_AMD64_R13B, "r13b");
        addReg(CV_AMD64_R14B, "r14b");
        addReg(CV_AMD64_R15B, "r15b");
        addReg(CV_AMD64_R8W, "r8w");
        addReg(CV_AMD64_R9W, "r9w");
        addReg(CV_AMD64_R10W, "r10w");
        addReg(CV_AMD64_R11W, "r11w");
        addReg(CV_AMD64_R12W, "r12w");
        addReg(CV_AMD64_R13W, "r13w");
        addReg(CV_AMD64_R14W, "r14w");
        addReg(CV_AMD64_R15W, "r15w");
        addReg(CV_AMD64_R8D, "r8d");
        addReg(CV_AMD64_R9D, "r9d");
        addReg(CV_AMD64_R10D, "r10d");
        addReg(CV_AMD64_R11D, "r11d");
        addReg(CV_AMD64_R12D, "r12d");
        addReg(CV_AMD64_R13D, "r13d");
        addReg(CV_AMD64_R14D, "r14d");
        addReg(CV_AMD64_R15D, "r15d");
    }

    public static String intToRegister(int r) {
        String rn = regNames.get(r);
        return rn != null ? rn : String.format("(r#%d)", r);
    }
}
