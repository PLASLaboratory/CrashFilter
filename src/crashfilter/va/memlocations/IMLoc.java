package crashfilter.va.memlocations;

import crashfilter.va.MLocAnalysis.IALoc;

public interface IMLoc extends IALoc {
    MLocTypes getMLocType();
}
