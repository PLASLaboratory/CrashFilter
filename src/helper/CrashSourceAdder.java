package helper;

import java.util.ArrayList;
import java.util.List;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.reil.OperandSize;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

public class CrashSourceAdder {
	
    private static ReilInstruction addedCrashInstSrc;
    private long crashReilAddr ;
    
	public static List<InstructionGraphNode> getInstructionlist( ILatticeGraph<InstructionGraphNode> graph , Long crashAddr)
	{
		List<InstructionGraphNode> originalList = graph.getNodes();
		List<InstructionGraphNode> InstructionGraphNodes = new ArrayList<InstructionGraphNode>();
		InstructionGraphNode crashInstruction = null;
		boolean addFlag = false;
		
		long preInstAddr= 0x00;
		ReilOperand toBeAddOperand = null;
		for(InstructionGraphNode inst : originalList)
		{
			long instAddr = inst.getInstruction().getAddress().toLong();
			
			if(addFlag && instAddr%0x100 == 0 )
			{
				Address addr = new Address(preInstAddr+1);
				crashInstruction = makeCrashSrcInstruction(addr,toBeAddOperand);
				InstructionGraphNodes.add(crashInstruction);
				addFlag = false;
			}
			
			if(instAddr%0x100 == 0 && instAddr/0x100 == crashAddr)
			{
				addFlag = true;
				toBeAddOperand = inst.getInstruction().getFirstOperand();				
			}
			preInstAddr = instAddr;
			
			InstructionGraphNodes.add(inst);
		}
		return InstructionGraphNodes;
	}

	
	public static InstructionGraphNode getInstruction( ILatticeGraph<InstructionGraphNode> graph , Long crashAddr)
	{
		List<InstructionGraphNode> originalList = graph.getNodes();
		InstructionGraphNode crashInstruction = null;
		boolean addFlag = false;
		
		long preInstAddr= 0x00;
		ReilOperand toBeAddOperand = null;
		for(InstructionGraphNode inst : originalList)
		{
			long instAddr = inst.getInstruction().getAddress().toLong();
			
			if(addFlag && instAddr%0x100 == 0 )
			{
				Address addr = new Address(preInstAddr+1);
				crashInstruction = makeCrashSrcInstruction(addr,toBeAddOperand);
				addFlag = false;
				break;
			}
			
			if(instAddr%0x100 == 0 && instAddr/0x100 == crashAddr)
			{
				addFlag = true;
				toBeAddOperand = inst.getInstruction().getFirstOperand();				
			}
			preInstAddr = instAddr;
			
		}
		return crashInstruction;
	}
	
	public static long getNextAddrOfCrash( ILatticeGraph<InstructionGraphNode> graph , Long crashAddr)
	{
		List<InstructionGraphNode> originalList = graph.getNodes();
		InstructionGraphNode crashInstruction = null;
		boolean addFlag = false;
		
		long preInstAddr= 0x00;
		ReilOperand toBeAddOperand = null;
		
		long nextAddrOfCrash=0;
		
		for(InstructionGraphNode inst : originalList)
		{
			long instAddr = inst.getInstruction().getAddress().toLong();
			
			if(addFlag && instAddr%0x100 == 0 )
			{
				Address addr = new Address(preInstAddr+1);
				crashInstruction = makeCrashSrcInstruction(addr,toBeAddOperand);
				addFlag = false;
				nextAddrOfCrash = inst.getInstruction().getAddress().toLong();
				break;
			}
			
			if(instAddr%0x100 == 0 && instAddr/0x100 == crashAddr)
			{
				addFlag = true;
				toBeAddOperand = inst.getInstruction().getFirstOperand();				
			}
			preInstAddr = instAddr;
			
		}
		return nextAddrOfCrash;
	}
	
	
	private static InstructionGraphNode makeCrashSrcInstruction(Address crashAddr ,ReilOperand reilOperand) {
		ReilOperand firstOperand = new ReilOperand(OperandSize.OPERAND_SIZE_DWORD, "EMPTY");
		ReilOperand secondOperand = new ReilOperand(OperandSize.OPERAND_SIZE_DWORD, "EMPTY");
		ReilOperand destOperand = reilOperand;
		
		ReilInstruction reilInstruction = new ReilInstruction(crashAddr, "str", firstOperand,secondOperand,destOperand);
		InstructionGraphNode inst = new InstructionGraphNode(reilInstruction);
		return inst;
	}
}
