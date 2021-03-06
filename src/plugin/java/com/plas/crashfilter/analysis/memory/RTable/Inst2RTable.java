package plugin.java.com.plas.crashfilter.analysis.memory.RTable;

import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;

import java.util.AbstractMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class Inst2RTable	extends AbstractMap<ReilInstruction, RTable>
							implements Map<ReilInstruction, RTable> 
{
	
	Inst2RTable(){
		tableEntries = new HashSet<java.util.Map.Entry<ReilInstruction, RTable>>();
	}
	Set<java.util.Map.Entry<ReilInstruction, RTable>> tableEntries;
	
	public RTable put(ReilInstruction e, RTable rt){
		tableEntries.add(new AbstractMap.SimpleEntry<ReilInstruction,RTable>(e, rt));
		return rt;
	}
	
	@Override
	public Set<java.util.Map.Entry<ReilInstruction, RTable>> entrySet() {
		return tableEntries; 
	}
}
