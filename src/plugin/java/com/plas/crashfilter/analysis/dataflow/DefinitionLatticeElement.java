package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeElement;

/**
 * Created by User on 2017-08-07.
 */
public class DefinitionLatticeElement implements ILatticeElement<DefinitionLatticeElement> {

    @Override
    public boolean equals(DefinitionLatticeElement latticeElement) {
        return false;
    }

    @Override
    public boolean lessThan(DefinitionLatticeElement latticeElement) {
        return false;
    }
}
