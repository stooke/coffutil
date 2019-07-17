package com.redhat.coffutil;

import java.io.PrintStream;
import java.nio.ByteBuffer;

class PEOptionalHeader32 {

    /**
     // from https://wiki.osdev.org/PE
     // 1 byte aligned
     struct Pe32OptionalHeader {
     uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
     uint8_t  mMajorLinkerVersion;
     uint8_t  mMinorLinkerVersion;
     uint32_t mSizeOfCode;
     uint32_t mSizeOfInitializedData;
     uint32_t mSizeOfUninitializedData;
     uint32_t mAddressOfEntryPoint;
     uint32_t mBaseOfCode;
     uint32_t mBaseOfData;
     uint32_t mImageBase;
     uint32_t mSectionAlignment;
     uint32_t mFileAlignment;
     uint16_t mMajorOperatingSystemVersion;
     uint16_t mMinorOperatingSystemVersion;
     uint16_t mMajorImageVersion;
     uint16_t mMinorImageVersion;
     uint16_t mMajorSubsystemVersion;
     uint16_t mMinorSubsystemVersion;
     uint32_t mWin32VersionValue;
     uint32_t mSizeOfImage;
     uint32_t mSizeOfHeaders;
     uint32_t mCheckSum;
     uint16_t mSubsystem;
     uint16_t mDllCharacteristics;
     uint32_t mSizeOfStackReserve;
     uint32_t mSizeOfStackCommit;
     uint32_t mSizeOfHeapReserve;
     uint32_t mSizeOfHeapCommit;
     uint32_t mLoaderFlags;
     uint32_t mNumberOfRvaAndSizes;
     };
     **/

    private int mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
    private int mMajorLinkerVersion;
    private int mMinorLinkerVersion;
    private int mSizeOfCode;
    private int mSizeOfInitializedData;
    private int mSizeOfUninitializedData;
    private int mAddressOfEntryPoint;
    private int mBaseOfCode;
    private int mBaseOfData;
    private int mImageBase;
    private int mSectionAlignment;
    private int mFileAlignment;
    private int mMajorOperatingSystemVersion;
    private int mMinorOperatingSystemVersion;
    private int mMajorImageVersion;
    private int mMinorImageVersion;
    private int mMajorSubsystemVersion;
    private int mMinorSubsystemVersion;
    private int mWin32VersionValue;
    private int mSizeOfImage;
    private int mSizeOfHeaders;
    private int mCheckSum;
    private int mSubsystem;
    private int mDllCharacteristics;
    private int mSizeOfStackReserve;
    private int mSizeOfStackCommit;
    private int mSizeOfHeapReserve;
    private int mSizeOfHeapCommit;
    private int mLoaderFlags;
    private int mNumberOfRvaAndSizes;

    PEOptionalHeader32(ByteBuffer in) {
        int offset = in.position();
        mMagic = in.getShort(); // 0x010b - PE32, 0x020b - PE32+ (64 bit)
        mMajorLinkerVersion = in.get();
        mMinorLinkerVersion = in.get();
        mSizeOfCode = in.getInt();
        mSizeOfInitializedData = in.getInt();
        mSizeOfUninitializedData = in.getInt();
        mAddressOfEntryPoint = in.getInt();
        mBaseOfCode = in.getInt();
        mBaseOfData = in.getInt();
        mImageBase = in.getInt();
        mSectionAlignment = in.getInt();
        mFileAlignment = in.getInt();
        mMajorOperatingSystemVersion = in.getShort();
        mMinorOperatingSystemVersion = in.getShort();
        mMajorImageVersion = in.getShort();
        mMinorImageVersion = in.getShort();
        mMajorSubsystemVersion = in.getShort();
        mMinorSubsystemVersion = in.getShort();
        mWin32VersionValue = in.getInt();
        mSizeOfImage = in.getInt();
        mSizeOfHeaders = in.getInt();
        mCheckSum = in.getInt();
        mSubsystem = in.getShort();
        mDllCharacteristics = in.getShort();
        mSizeOfStackReserve = in.getInt();
        mSizeOfStackCommit = in.getInt();
        mSizeOfHeapReserve = in.getInt();
        mSizeOfHeapCommit = in.getInt();
        mLoaderFlags = in.getInt();
        mNumberOfRvaAndSizes = in.getInt();
    }

    String validate() {
        return null;
    }

    void dump(PrintStream out) {
        out.println("PEOptionalHeader32 found");
    }
}

