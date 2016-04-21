package crashfilter.va.MLocAnalysis.RTable;

import java.util.List;

import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;

public class RTableLattice implements ILattice<RTableLatticeElement, Object>{

	@Override
	public RTableLatticeElement combine(	List<IInfluencingState<RTableLatticeElement, Object>> states) 
	{		
		RTableLatticeElement combinedState = new RTableLatticeElement();
		
		//Union all the predecessor's state
		for ( IInfluencingState<RTableLatticeElement, Object> state : states ){
			combinedState.combine(state.getElement());				
		}
		
		return combinedState;
		
	}

}
