package plugin.java.com.plas.crashfilter.util;

import java.util.HashMap;

public class CountInstructionHashMap extends HashMap<String, Integer> {

    @Override
    public Integer put(String key, Integer value) {
        // TODO Auto-generated method stub
        if (this.get(key) == null)
            return super.put(key, value);
        else {
            Integer i = this.get(key);
            i++;
            return super.put(key, i);
        }
    }

}
