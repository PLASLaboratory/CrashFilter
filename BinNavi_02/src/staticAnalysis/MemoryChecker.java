package staticAnalysis;

import java.util.Set;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import crashfilter.va.MLocAnalysis.IValue;
import crashfilter.va.MLocAnalysis.MLocLatticeElement;
import crashfilter.va.MLocAnalysis.env.Env;
import crashfilter.va.MLocAnalysis.env.EnvLatticeElement;
import crashfilter.va.memlocations.MLocException;
import crashfilter.va.memlocations.StructuredMLoc;
import crashfilter.va.regs.ActualReg;

public class MemoryChecker {
	IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult;
	public void setMLocResult(IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult)
	{
		this.mLocResult = mLocResult;
	}
	public boolean differentMemoryCheckEnv(InstructionGraphNode inst_stm, InstructionGraphNode inst_ldm ) throws MLocException
	{	
		//함수이름을 좀더 수정할 필요 있음 
		
		if(stackNHeapRelationCheck(inst_ldm, inst_stm))
		{
			return true;
		}
		if(isFromStackMemoryEnv(inst_ldm) && isToStackMemoryEnv(inst_stm))
		{			
			return isDeffrentStack(inst_ldm, inst_stm);
		}
		
		if(isdiffrent(inst_stm, inst_ldm))
		{
			return true;
		}
		return false;
	}
	private boolean stackNHeapRelationCheck(InstructionGraphNode inst_stm, InstructionGraphNode inst_ldm) throws MLocException
	{
		return (isFromStackMemoryEnv(inst_ldm) && isToHeapMemoryEnv(inst_stm)) || (isFromHeapMemoryEnv(inst_ldm) && isToStackMemoryEnv(inst_stm));		
	}
	private boolean isdiffrent(InstructionGraphNode inst1, InstructionGraphNode inst2) throws MLocException {
		
		ReilInstruction i1 = inst1.getInstruction();
		ReilInstruction i2 = inst2.getInstruction();
		
		if(  (i1.getMnemonic().equals("stm") && i2.getMnemonic().equals("ldm")))
		{
		
			Set<IValue> valueSet1 = getIValueSetAbout(inst1);
			Set<IValue> valueSet2 = getIValueSetAbout(inst2);
			if(valueSet1 == null || valueSet2 == null)
			{
				//LogConsole.log("\n");
				return true;
			}
			for(IValue value1 : valueSet1)	{			
				for(IValue value2 : valueSet2)
				{
					if(value1 instanceof StructuredMLoc && value2 instanceof StructuredMLoc)
					{
						StructuredMLoc s1 = (StructuredMLoc) value1;
						StructuredMLoc s2 = (StructuredMLoc) value2;
						if(s1.getReg2().equals( s2.getReg2()) && 
								( s1.getReg2().equals(ActualReg.ESP) || 
										s1.getReg2().equals(ActualReg.STACK) || s1.getReg2().equals(ActualReg.SP)))
						{
							if(s1.getC2().getValue() == s2.getC2().getValue())
							{
								return false;
							}
						}
					}
				}
			}
			return true;
		  }
		return false;
	}
	private boolean isDeffrentStack(InstructionGraphNode inst1, InstructionGraphNode inst2) throws MLocException
	{
		Set<IValue> valueSet1 = getIValueSetAbout(inst1);
		Set<IValue> valueSet2 = getIValueSetAbout(inst2);
		if(valueSet1 == null || valueSet2 == null)
		{
			return true;
		}
		
	
		for(IValue value1 : valueSet1)	{			
			for(IValue value2 : valueSet2)
			{
				if(value1 instanceof StructuredMLoc && value2 instanceof StructuredMLoc) 
				{
					StructuredMLoc s1 = (StructuredMLoc) value1;
					StructuredMLoc s2 = (StructuredMLoc) value2;
					if(s1.getReg2().equals(new ActualReg("stack")) && s2.getReg2().equals(new ActualReg("stack")))
					{
						//both structuredMLoc is stack. 
						if(s1.getC2().getValue() == s2.getC2().getValue())
						{
							return false;
						}						
					}
					if(s1.getReg2().equals(new ActualReg("SP")) && s2.getReg2().equals(new ActualReg("SP")))
					{
						//both structuredMLoc is stack. 
						if(s1.getC2().getValue() == s2.getC2().getValue())
						{
							return false;
						}						
					}
					if(s1.getReg2().equals(new ActualReg("esp")) && s2.getReg2().equals(new ActualReg("esp")))
					{
						//both structuredMLoc is stack. 
						if(s1.getC2().getValue() == s2.getC2().getValue())
						{
							return false;
						}						
					}
				}
			}
		}
		return true;
		
	}
	private Set<IValue> getIValueSetAbout(InstructionGraphNode inst) throws MLocException
	{
		//ldm / stm 함수 구분, 
		MLocLatticeElement envLatticeElement = mLocResult.getState(inst);
		Env env = envLatticeElement.getEnv();
		ReilInstruction reilInst = inst.getInstruction();

		if(reilInst.getMnemonic().equals("ldm"))
		{
			StructuredMLoc loc = StructuredMLoc.newStructuredMLoc(reilInst.getFirstOperand());
			return env.get(loc);
		}
		else if(reilInst.getMnemonic().equals("stm"))
		{
			StructuredMLoc loc = StructuredMLoc.newStructuredMLoc(reilInst.getThirdOperand());
			return env.get(loc);
		}
		
		return null;
	}

	private boolean isFromStackMemoryEnv(InstructionGraphNode inst) throws MLocException
	{
		ReilInstruction reilInst = inst.getInstruction();
		if(reilInst.getMnemonic() != "ldm")
		{
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory( reilInst.getFirstOperand().getValue());
		if(v==null)
		{
			return false;
		}
		if(v.equals(new ActualReg("stack")) )
		{
			return true;
		}
		return false;
	}
	
	private boolean isFromHeapMemoryEnv(InstructionGraphNode inst) throws MLocException
	{
		ReilInstruction reilInst = inst.getInstruction();
		if(reilInst.getMnemonic() != "ldm")
		{
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory( reilInst.getFirstOperand().getValue());
		if(v==null)
		{
			return false;
		}
		if(v.equals(new ActualReg("heap")))
		{
			return true;
		}
		return false;
	}
	
	private boolean isToStackMemoryEnv(InstructionGraphNode inst) throws MLocException
	{
		ReilInstruction reilInst = inst.getInstruction();
		if(reilInst.getMnemonic() != "stm")
		{
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory( reilInst.getThirdOperand().getValue());
		if(v==null)
		{
			return false;
		}
		if(v.equals(new ActualReg("stack")) )
		{
			return true;
		}
		return false;
	}
	
	private boolean isToHeapMemoryEnv(InstructionGraphNode inst) throws MLocException
	{
		ReilInstruction reilInst = inst.getInstruction();
		if(reilInst.getMnemonic() != "stm")
		{
			return false;
		}
		MLocLatticeElement mLocLatticeElement = mLocResult.getState(inst);
		Env env = mLocLatticeElement.getEnv();
		IValue v = env.checkStackOrHEapMemory( reilInst.getThirdOperand().getValue());
		if(v==null)
		{
			return false;
		}
		if(v.equals(new ActualReg("heap")))
		{
			return true;
		}
		return false;
	}
	
	
}
