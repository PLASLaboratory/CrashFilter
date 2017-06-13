package plugin.java.com.plas.crashfilter.analysis.memory.mloc;

import plugin.java.com.plas.crashfilter.analysis.memory.IALoc;

public interface IMLoc extends IALoc {
    MLocTypes getMLocType();
}
