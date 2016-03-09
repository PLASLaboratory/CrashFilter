package crashfilter.va.MLocAnalysis.env;

import java.util.*;
import com.google.security.zynamics.binnavi.API.reil.ReilEdge;

import crashfilter.va.MLocAnalysis.IValue;
import crashfilter.va.MLocAnalysis.RTable.RTable;


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
