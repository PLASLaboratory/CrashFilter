package plugin.java.com.plas.crashfilter.analysis.memory;

import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import plugin.java.com.plas.crashfilter.analysis.helper.AddressTransferHelper;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.IMLoc;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocTypes;

public class Val implements IMLoc, IValue, IALoc {
    int size;
    int value;

    public Val(int v) {
        this(4, v);
    }

    Val(int s, int v) {
        if (!(s == 1 | s == 2 | s == 4 | s == 8)) // number of bytes
            size = 4;
        else
            size = s;
        value = v;
    }

    // add two consts
    public static Val add(Val v1, Val v2) {
        int size = v1.size; // temporary, should be adjusted later
        return new Val(size, v1.value + v2.value);
    }

    public static Val sub(Val v1, Val v2) {
        int size = v1.size; // temporary, should be adjusted later
        return new Val(size, v1.value - v2.value);
    }

    public int getValue() {
        return this.value;
    }

    public static Val newVal(ReilOperand op) {
        int val = AddressTransferHelper.hexString2Int(op.getValue());
        return new Val(val);
    }


    public MLocTypes getMLocType() {
        return MLocTypes.ValConst;
    }

    @Override
    public String toString() {
        // TODO Auto-generated method stub
        return "[Val : " + value + "]";
    }

    @Override
    public int hashCode() {
        // TODO Auto-generated method stub
        return new Integer(this.value).hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        // TODO Auto-generated method stub
        if (this.getClass() != obj.getClass()) {
            return false;
        }
        Val o = (Val) obj;

        return o.value == this.value;
    }

}
