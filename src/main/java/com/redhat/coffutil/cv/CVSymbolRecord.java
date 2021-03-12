package com.redhat.coffutil.cv;

import java.nio.ByteBuffer;

public class CVSymbolRecord {

    private final int pos;
    private final int cmd;
    private final int len;
    private final String description;
    private final ByteBuffer data;

    CVSymbolRecord(int pos, int len, int cmd, String description, ByteBuffer data) {
        this.pos = pos;
        this.cmd = cmd;
        this.len = len;
        this.description = description;
        this.data = data;
    }

    public String toString() {
        return this.description != null ? this.description : "";
    }

    public int getPos() {
        return pos;
    }

    public int getCmd() {
        return cmd;
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
