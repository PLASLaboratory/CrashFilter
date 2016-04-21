package helper;

import java.util.ArrayList;
import java.util.List;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import data.ReilInstructionResolve;

public class HeapChecker
{
	private List<String> allocList ;
	private List<Instruction> heapInstList = new ArrayList<Instruction>();	
	private ILatticeGraph<InstructionGraphNode> graph;
	private static HeapChecker heapChecker;
	
	public static HeapChecker initHeapChecker(ILatticeGraph<InstructionGraphNode> graph, Function function)
	{
		heapChecker = new HeapChecker(graph, function);
		return heapChecker;
	}
	
	public static HeapChecker getHeapChecker()
	{
		return heapChecker;
	}
	public List<String> getAllocList() {
		return allocList;
	}
	public List<Instruction> getHeapInstList() {
		return heapInstList;
	}
	public void setGraph( ILatticeGraph<InstructionGraphNode> graph)
	{
		this.graph = graph;
	}
	public HeapChecker(ILatticeGraph<InstructionGraphNode> graph, Function function)
	{
		setGraph(graph);
		
		allocList = new ArrayList<>();
		////// file-
		allocList.add("alloc");
		allocList.add("malloc");
		allocList.add("calloc");
		allocList.add("realloc");
		
		allocList.add("xalloc");
		allocList.add("xmalloc");
		allocList.add("xcalloc");
		allocList.add("xrealloc");
		
		allocList.add("HeapAlloc");
		allocList.add("heapalloc");
		allocList.add("farmalloc");
		allocList.add("farcalloc");
		
		/////////////
		
		allocList.add("ds: [__imp__malloc]");
		
		/////////////
		allocList.add("_alloc");
		allocList.add("_malloc");
		allocList.add("_calloc");
		allocList.add("_realloc");
		
		allocList.add("__heap_alloc");
		allocList.add("__far_malloc");
		allocList.add("__far_calloc");
		
		//////
		
		allocList.add("ds:alloc");
		allocList.add("ds:malloc");
		allocList.add("ds:calloc");
		allocList.add("ds:realloc");
		
		allocList.add("ds:xalloc");
		allocList.add("ds:xmalloc");
		allocList.add("ds:xcalloc");
		allocList.add("ds:xrealloc");
		
		allocList.add("ds:HeapAlloc");
		allocList.add("ds:heapalloc");
		allocList.add("ds:farmalloc");
		allocList.add("ds:farcalloc");
		////
		findHeapAllocation(function);
	}
	public boolean isAllocateFuction(String str)
	{
		return allocList.contains(str);
	}
	
	public boolean eaxHeapMemoryCheck(long reilAddr)
	{
		reilAddr /= 0x100;
		for(Instruction inst : heapInstList)
		{
			if (inst.getAddress().toLong() == reilAddr)
			{
				return true;
			}
		}
		return false;			
	}
	
	public void findHeapAllocation(Function function)
	{		
		List<InstructionGraphNode> lg =graph.getNodes();
		Address funcAddr;
		boolean savePoint = false;
		
		for(InstructionGraphNode ign : lg)
		{		
			
			funcAddr = ign.getInstruction().getAddress();
			long funcaddrl = funcAddr.toLong();
			if(funcaddrl % 0x100 == 0)
			{			
				funcaddrl /= 0x100;
				Instruction inst = ReilInstructionResolve.findNativeInstruction(function, funcaddrl);
				
				if(savePoint)
				{
					heapInstList.add(inst);
					savePoint = false;
				}
				
				for(Operand op : inst.getOperands())
				{
					if(isAllocateFuction(op.toString()))
					{
						savePoint = true;
					}
				}
			}	
		}
	}
}