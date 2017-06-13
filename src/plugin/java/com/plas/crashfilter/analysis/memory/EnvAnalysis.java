package plugin.java.com.plas.crashfilter.analysis.memory;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.*;
import plugin.java.com.plas.crashfilter.analysis.helper.HeapChecker;
import plugin.java.com.plas.crashfilter.analysis.helper.MemoryCounter;
import plugin.java.com.plas.crashfilter.analysis.memory.env.Env;
import plugin.java.com.plas.crashfilter.analysis.memory.env.EnvLattice;
import plugin.java.com.plas.crashfilter.analysis.memory.env.EnvLatticeElement;
import plugin.java.com.plas.crashfilter.analysis.memory.env.EnvManager;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;

import java.util.List;

public class EnvAnalysis {
	private ILatticeGraph<InstructionGraphNode> graph;
	private Function function;
	private HeapChecker heapChecker = HeapChecker.initHeapChecker(graph, function);
	
	
	public void LocAnalysis( ILatticeGraph<InstructionGraphNode> graph , Function function ){
		this.graph = graph;
		this.function = function;
	}
	
	public EnvAnalysis( ILatticeGraph<InstructionGraphNode> graph ){
		this.graph = graph;
		
	}

	public IStateVector<InstructionGraphNode, EnvLatticeElement> envAnalysis() throws MLocException
	{
		 EnvLattice lattice;
		 IStateVector<InstructionGraphNode, EnvLatticeElement> startVector;
		 IStateVector<InstructionGraphNode, EnvLatticeElement> endVector;
		 
		 ITransformationProvider<InstructionGraphNode, EnvLatticeElement> transferFunction;
		 DownWalker<InstructionGraphNode> walker;
		 MonotoneSolver<InstructionGraphNode, EnvLatticeElement, Object, EnvLattice> solver;


		 lattice = new EnvLattice();
		 
		 startVector = initializeState(graph);
		 transferFunction = new EnvTransferFunction();
		 walker = new DownWalker<InstructionGraphNode>();
		 solver = new MonotoneSolver<InstructionGraphNode, EnvLatticeElement, Object, EnvLattice>(
				 graph, lattice, startVector, transferFunction, walker
				 );
		 endVector = solver.solve();
		 
		 return endVector;
	}
	 
	
	private IStateVector<InstructionGraphNode, EnvLatticeElement> initializeState(
			ILatticeGraph<InstructionGraphNode> graph2) throws MLocException {
		int i=0;
		IStateVector<InstructionGraphNode, EnvLatticeElement> startVector = 
				 new DefaultStateVector<InstructionGraphNode, EnvLatticeElement>();
		
		List<InstructionGraphNode> instList = graph2.getNodes();
		EnvLatticeElement state ;
		
		
		
		for (InstructionGraphNode inst : graph.getNodes()){
			 
			state = new EnvLatticeElement();
			
			Env env = new Env();
			EnvManager eManager = EnvManager.getEnvManager();
			eManager.setEnv(env);			

			env = eManager.initFirst();			
			env = eManager.init();				
		
			state.setInst(inst);
			state.setEnv(env);
			
			startVector.setState(inst, state);
		}
		
		return startVector;
	}
	public class EnvTransferFunction implements ITransformationProvider<InstructionGraphNode, EnvLatticeElement>{
		public EnvLatticeElement transform(
				InstructionGraphNode node,
				EnvLatticeElement currentState,
				EnvLatticeElement inputState
				) {

			//TODO
			//System.out.println(node.getInstruction());
			//LogConsole.log(node.getInstruction()+"\n");
			
			EnvLatticeElement transformedState = new EnvLatticeElement();
			
			Env inputEnv = inputState.getEnv();
			Env currentEnv = currentState.getEnv();
			Env result = null;
			
			if(inputEnv.size() == 0)
			{
				result = currentEnv;
			}
			else
			{
				result = inputEnv;
			}
						
			EnvManager eManager = null;
			
			long instLong = node.getInstruction().getAddress().toLong();
		
			
			if(heapChecker.eaxHeapMemoryCheck(instLong))
			{
				
				System.out.println("Heap Checking!");
				try {
					eManager = EnvManager.getEnvManager();
					eManager.setEnv(result);
					result = eManager.initEax2Heap();
				} catch (MLocException e) {
					e.printStackTrace();
				}
			}
			
			
			try {
				eManager = EnvManager.getEnvManager();
				eManager.oneReilInst(result, node.getInstruction());				
				result = eManager.getEnv();
			} catch (MLocException e) {
				e.printStackTrace();
			}
		
			
			transformedState.setInst(node);
			transformedState.setEnv(result);
			
			currentState.setEnv(result);

			//result.printEnv();
			return transformedState;
		}
	}
	
	public void printEnv(IStateVector<InstructionGraphNode, EnvLatticeElement> endVector){	 

		MemoryCounter memoryCounter = MemoryCounter.getMemoryCounter();
		EnvLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 LogConsole.log("instruction : ");
			 LogConsole.log(inst.getInstruction().toString());
			 LogConsole.log("\n");		 
			 state.getEnv().printEnv();
		}		
		
		memoryCounter.printMemoryCounter();

	}

	public IRegister isStackOrHeap(IStateVector<InstructionGraphNode, EnvLatticeElement> endVector){	 
		
		
		return null;
		
	}
	
	public void deleteTempReg(IStateVector<InstructionGraphNode, EnvLatticeElement> endVector)
	{
		EnvLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 state.getEnv().deleteTempReg();
		 }
	}
	
	public HeapChecker findHeapAllocation(Function function)
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
				
				//System.out.println(inst);
				if(savePoint)
				{
					heapChecker.getHeapInstList().add(inst);
					savePoint = false;
				}
				
				
				for(Operand op : inst.getOperands())
				{
					//System.out.println(op);
					if(heapChecker.isAllocateFuction(op.toString()))
					{
						savePoint = true;
					}
				}
			}	
		}
		
		return heapChecker;
	}
	
	public void deleteBottomSymbol(IStateVector<InstructionGraphNode, EnvLatticeElement> vector)
	{
		EnvLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = vector.getState(inst);
			 state.getEnv().deleteNullNBottom();
		}
	}
	
	
	
}
