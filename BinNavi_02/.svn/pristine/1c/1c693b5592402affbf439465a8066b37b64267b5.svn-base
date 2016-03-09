package crashfilter.va.MLocAnalysis.env;

import java.util.List;

import com.google.security.zynamics.binnavi.API.reil.ReilBlock;
import com.google.security.zynamics.binnavi.API.reil.ReilEdge;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;

import crashfilter.va.MLocAnalysis.RTable.Inst2RTable;
import crashfilter.va.MLocAnalysis.RTable.RTable;

public class EdgeMapper {

	// using before merge(transfer function) for find source instruction's rTables
	// edgeMap
	// key : Edge
	// value : 
	//          Edge's source => BB
	//			BB's last Instruction => INST
	//			INST's rTable => value
	

	private Edge2RTable edgeMap =null;	
	private Inst2RTable instMap = null;
	
	public static EdgeMapper EMAPPER= null;
	List<ReilEdge> edgeList =null;
	
	
	private EdgeMapper(List<ReilEdge> rEdgeList)
	{
		edgeList = rEdgeList;
		initList(rEdgeList);
	}
	private void initList(List<ReilEdge> rEdgeList) {
		// TODO Auto-generated method stub
		for(ReilEdge edge : rEdgeList)
		{
			ReilInstruction lastInstructionOfSrc = getLastInstruction(edge.getSource());
			RTable value = instMap.get(lastInstructionOfSrc);
			edgeMap.put(edge, value);
		}
	}
	private ReilInstruction getLastInstruction ( ReilBlock rb)
	{
		List<ReilInstruction> rl = rb.getInstructions();
		int size = rl.size();
		return rl.get(size-1);		
	}
	public static EdgeMapper getEdgeMapper(List<ReilEdge> rEdgeList)
	{
		if( EMAPPER == null)
		{
			//만들어준다
			EMAPPER = new EdgeMapper(rEdgeList);
			return EMAPPER;
		}
		else
		{
			//준다
			return EMAPPER;
		}
	}
	
	
}
