package com.redhat.coffutil.cv;

import java.nio.ByteBuffer;

public class CVTypeRecord {

    private final int pos;
    private final int idx;
    private final int leafType;
    private final int len;
    private final String description;
    private final ByteBuffer data;

    CVTypeRecord(int pos, int idx, int leafType, int len, String description, ByteBuffer data) {
        this.pos = pos;
        this.idx = idx;
        this.leafType = leafType;
        this.len = len;
        this.description = description;
        this.data = data;
    }

    public String toString() {
        return this.description != null ? this.description : "";
    }

    int getPos() {
        return pos;
    }

    int getIdx() {
        return idx;
    }

    int getLeafType() {
        return leafType;
    }

    int getLen() {
        return len;
    }

    String getDescription() {
        return description;
    }

    ByteBuffer getData() {
        return data;
    }
}
