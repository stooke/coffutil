package com.redhat.coffutil.cv;

import com.redhat.coffutil.msf.HexDump;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import static com.redhat.coffutil.cv.CVConstants.LF_ENUMERATE;
import static com.redhat.coffutil.cv.CVConstants.LF_FIELDLIST;

public class CVTypeSection {

    private final List<CVTypeRecord> records = new ArrayList<>(1000);

    void addRecord(CVTypeRecord record) {
        records.add(record);
    }
    public void dump(PrintStream out) {
        for (CVTypeRecord record : records) {
            out.format("0x%05x 0x%04x len=%d %s\n", record.getIdx(), record.getLeafType(), record.getLen(), record.toString());
            if (record.getLeafType() == LF_FIELDLIST || record.getLeafType() == LF_ENUMERATE) {
                String dump = new HexDump().makeLines(record.getData(), 0, 0, record.getLen());
                out.print(dump);
            }
        }
    }
}
