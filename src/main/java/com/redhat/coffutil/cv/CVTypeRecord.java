package com.redhat.coffutil.cv;

import java.nio.ByteBuffer;

public class CVTypeRecord {

    private final int idx;
    private final int leafType;
    private final int len;
    private final String description;
    private final ByteBuffer data;

    CVTypeRecord(int idx, int leafType, int len, String description, ByteBuffer data) {
        this.idx = idx;
        this.leafType = leafType;
        this.len = len;
        this.description = description;
        this.data = data;
    }

    public String toString() {
        return this.description != null ? this.description : "";
    }

    public int getIdx() {
        return idx;
    }

    public int getLeafType() {
        return leafType;
    }

    public int getLen() {
        return len;
    }

    public String getDescription() {
        return description;
    }

    public ByteBuffer getData() {
        return data;
    }
}
