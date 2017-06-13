package plugin.java.com.plas.crashfilter.util;

import java.util.HashMap;

public class CountInstruction extends HashMap<Integer, CrashPoint> {

    @Override
    public CrashPoint put(Integer key, CrashPoint value) {
        return super.put(key, value);
    }

}
