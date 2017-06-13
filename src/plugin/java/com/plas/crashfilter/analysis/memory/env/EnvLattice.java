package plugin.java.com.plas.crashfilter.analysis.memory.env;

import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;

import java.util.List;

public class EnvLattice implements ILattice<EnvLatticeElement, Object>{

	@Override
	public EnvLatticeElement combine(
		List<IInfluencingState<EnvLatticeElement, Object>> states) {
			
		EnvLatticeElement combinedState = new EnvLatticeElement();
		

		for ( IInfluencingState<EnvLatticeElement, Object> state : states ){
			combinedState.combine(state.getElement());				
		}
		
		return combinedState;
	}

}
