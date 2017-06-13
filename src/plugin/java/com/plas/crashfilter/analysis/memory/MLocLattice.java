package plugin.java.com.plas.crashfilter.analysis.memory;

import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;

import java.util.List;

public class MLocLattice implements ILattice<MLocLatticeElement, Object> {
	
	@Override
	public MLocLatticeElement combine(List<IInfluencingState<MLocLatticeElement, Object>> states) {
		MLocLatticeElement combinedState = new MLocLatticeElement();
		for ( IInfluencingState<MLocLatticeElement, Object> state : states ){
			combinedState.combine(state.getElement());
		}
		return combinedState;
	}


}
