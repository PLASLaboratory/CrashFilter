package crashfilter.va.MLocAnalysis;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeElement;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import crashfilter.va.MLocAnalysis.RTable.RTable;
import crashfilter.va.MLocAnalysis.env.Env;

public class MLocLatticeElement implements ILatticeElement<MLocLatticeElement>{
	private InstructionGraphNode inst;
	private Env env;
	private RTable rTable;
	//getter & setter
	public MLocLatticeElement()
	{
		env = new Env();
		rTable = new RTable();
	}
	public Env getEnv()
	{
		return this.env;
	}
	public void setEnv(Env env)
	{
		this.env = env;
	}
	public RTable getRTable()
	{
		return this.rTable;
	}
	public void setRTable(RTable rTable)
	{
		this.rTable = rTable;
	}
	public void setInst(InstructionGraphNode inst)
	{
		this.inst = inst;
	}
	public InstructionGraphNode getInst()
	{
		return inst;
	}
	public void combine( MLocLatticeElement mLocLatticeElement)
	{
		env = env.combine(mLocLatticeElement.env);
		rTable = rTable.combine(mLocLatticeElement.rTable);
	}

	@Override
	public boolean equals(MLocLatticeElement mLocLatticeElement) {
		boolean returnValue = env.equals(mLocLatticeElement.env)&&rTable.equals(mLocLatticeElement.rTable); 
		return returnValue;
	}

	@Override
	public boolean lessThan(MLocLatticeElement mLocLatticeElement) {
		boolean returnValue = env.lessthan(mLocLatticeElement.env)||rTable.lessthan(mLocLatticeElement.rTable);
		return returnValue;
	}                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
	
}
