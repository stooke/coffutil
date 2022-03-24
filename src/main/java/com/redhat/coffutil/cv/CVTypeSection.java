package com.redhat.coffutil.cv;

import com.redhat.coffutil.CoffUtilContext;
import com.redhat.coffutil.msf.HexDump;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.redhat.coffutil.cv.CVConstants.T_BOOL08;
import static com.redhat.coffutil.cv.CVConstants.T_CHAR;
import static com.redhat.coffutil.cv.CVConstants.T_INT1;
import static com.redhat.coffutil.cv.CVConstants.T_INT2;
import static com.redhat.coffutil.cv.CVConstants.T_INT4;
import static com.redhat.coffutil.cv.CVConstants.T_INT8;
import static com.redhat.coffutil.cv.CVConstants.T_POINTER64;
import static com.redhat.coffutil.cv.CVConstants.T_QUAD;
import static com.redhat.coffutil.cv.CVConstants.T_REAL32;
import static com.redhat.coffutil.cv.CVConstants.T_REAL64;
import static com.redhat.coffutil.cv.CVConstants.T_SHORT;
import static com.redhat.coffutil.cv.CVConstants.T_VOID;
import static com.redhat.coffutil.cv.CVConstants.T_WCHAR;

public class CVTypeSection {

    private final List<CVTypeRecord> records = new ArrayList<>(1000);

    void addRecord(CVTypeRecord record) {
        records.add(record);
    }

    public void dump(PrintStream out) {
        for (CVTypeRecord record : records) {
            //out.format("0x%04x 0x%04x len=%-4d %s\n", record.getIdx(), record.getLeafType(), record.getLen(), record.toString());
            out.format("0x%04x 0x%04x %s\n", record.getPos(), record.getIdx(), record.toString());
            if (CoffUtilContext.getInstance().getDumpHex()) {
                String dump = new HexDump().makeLines(record.getData(), -record.getData().position(), record.getData().position(), record.getLen());
                out.print(dump);
            }
        }
    }

    private static final HashMap<Integer, String> primitiveTypeMap = new HashMap<>(20);
    static {
        primitiveTypeMap.put(T_VOID, "T_VOID");
        primitiveTypeMap.put(T_CHAR, "T_CHAR");
        primitiveTypeMap.put(T_SHORT, "T_SHORT");
        primitiveTypeMap.put(T_INT8, "T_INT8");
        primitiveTypeMap.put(T_INT4, "T_INT4");
        primitiveTypeMap.put(T_INT2, "T_INT2");
        primitiveTypeMap.put(T_INT1, "T_INT1");
        primitiveTypeMap.put(T_BOOL08, "T_BOOL08");
        primitiveTypeMap.put(T_QUAD, "T_QUAD");
        primitiveTypeMap.put(T_REAL32, "T_REAL32");
        primitiveTypeMap.put(T_REAL64, "T_REAL64");
        primitiveTypeMap.put(T_WCHAR, "T_WCHAR");
        primitiveTypeMap.put(T_POINTER64, "T_POINTER64");
    }

    public static String intToType(int idx) {
        if (primitiveTypeMap.containsKey(idx)) {
            return primitiveTypeMap.get(idx);
        } else {
            return String.format("0x%04x", idx);
        }
    }
}
