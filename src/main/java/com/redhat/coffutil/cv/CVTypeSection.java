package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.msf.HexDump;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class CVTypeSection {

    private final List<CVTypeRecord> records = new ArrayList<>(1000);

    void addRecord(CVTypeRecord record) {
        records.add(record);
    }

    public void dump(PrintStream out) {
        for (CVTypeRecord record : records) {
            //out.format("0x%04x 0x%04x len=%-4d %s\n", record.getIdx(), record.getLeafType(), record.getLen(), record.toString());
            out.format("0x%04x %s\n", record.getIdx(), record.toString());
            if (CoffUtilContext.getInstance().getDumpHex()) {
                String dump = new HexDump().makeLines(record.getData(), -record.getData().position(), record.getData().position(), record.getLen());
                out.print(dump);
            }
        }
    }
}
