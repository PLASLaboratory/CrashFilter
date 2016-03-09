package crashfilter.va.MLocAnalysis;

import java.util.List;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;

import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;

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
