package plugin.java.com.plas.crashfilter.analysis.memory.env;

import com.google.security.zynamics.binnavi.API.reil.ReilEdge;
import plugin.java.com.plas.crashfilter.analysis.memory.RTable.RTable;

import java.util.AbstractMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


public class Edge2RTable	extends AbstractMap<ReilEdge, RTable>
							implements Map<ReilEdge, RTable> 
{
	
	Edge2RTable(){
		tableEntries = new HashSet<java.util.Map.Entry<ReilEdge, RTable>>();
	}
	Set<java.util.Map.Entry<ReilEdge, RTable>> tableEntries;
	
	public RTable put(ReilEdge e, RTable rt){
		tableEntries.add(new AbstractMap.SimpleEntry<ReilEdge,RTable>(e, rt));
		return rt;
	}
	
	@Override
	public Set<java.util.Map.Entry<ReilEdge, RTable>> entrySet() {
		return tableEntries; 
	}
}
