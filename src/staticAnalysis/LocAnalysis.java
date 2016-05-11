package staticAnalysis;

import java.util.List;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.DefaultStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.DownWalker;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.ITransformationProvider;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import com.google.security.zynamics.binnavi.API.reil.mono.MonotoneSolver;

import crashfilter.va.MLocAnalysis.RTable.IRSetManager;
import crashfilter.va.MLocAnalysis.RTable.RTable;
import crashfilter.va.MLocAnalysis.RTable.RTableLattice;
import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;
import crashfilter.va.memlocations.MLocException;
import helper.HeapChecker;

public class LocAnalysis {
	private ILatticeGraph<InstructionGraphNode> graph;
	private Function function;
	private HeapChecker heapChecker = new HeapChecker(graph, function);
	
	
	public LocAnalysis( ILatticeGraph<InstructionGraphNode> graph , Function function ){
		this.graph = graph;
		this.function = function;
	}

	public IStateVector<InstructionGraphNode, RTableLatticeElement> locAnalysis() throws MLocException
	{ 
		 RTableLattice lattice;
		 IStateVector<InstructionGraphNode, RTableLatticeElement> startVector;
		 IStateVector<InstructionGraphNode, RTableLatticeElement> endVector;
		 
		 ITransformationProvider<InstructionGraphNode, RTableLatticeElement> transferFunction;
		 DownWalker<InstructionGraphNode> walker;
		 MonotoneSolver<InstructionGraphNode, RTableLatticeElement, Object, RTableLattice> solver;

		 lattice = new RTableLattice();
		 
		 startVector = initializeState(graph);
		 transferFunction = new LocTransferFunction();
		 walker = new DownWalker<InstructionGraphNode>();
		 solver = new MonotoneSolver<InstructionGraphNode, RTableLatticeElement, Object, RTableLattice>(
				 graph, lattice, startVector, transferFunction, walker
				 );
		 endVector = solver.solve();
		 
		 return endVector;
	}
	 
	
	private IStateVector<InstructionGraphNode, RTableLatticeElement> initializeState(
			ILatticeGraph<InstructionGraphNode> graph2) throws MLocException {

		IStateVector<InstructionGraphNode, RTableLatticeElement> startVector = 
				 new DefaultStateVector<InstructionGraphNode, RTableLatticeElement>();
		
		List<InstructionGraphNode> instList = graph2.getNodes();
		RTableLatticeElement state ;
		
		
		
		for (InstructionGraphNode inst : graph.getNodes()){
			 
			state = new RTableLatticeElement();
			
			RTable rtable = new RTable();
			IRSetManager irsm = IRSetManager.getIRSetManager();
			irsm.setRTable(rtable);
			

			rtable = irsm.initFirst();			
			rtable = irsm.init();			
			
			state.setInst(inst);
			state.setRTable(rtable);
			
			startVector.setState(inst, state);
		}
		
		return startVector;
	}
	public class LocTransferFunction implements ITransformationProvider<InstructionGraphNode, RTableLatticeElement>{
		@Override
		public RTableLatticeElement transform(
				InstructionGraphNode node,
				RTableLatticeElement currentState,
				RTableLatticeElement inputState
				) {

			
			RTableLatticeElement transformedState = new RTableLatticeElement();
			RTable inputRTable = inputState.getRTable();
			RTable currentRTable = currentState.getRTable();
			
			RTable result = inputRTable.combine(currentRTable);
			IRSetManager irsm = IRSetManager.getIRSetManager();		
			
			try {
				irsm.setRTable(result);
				irsm.oneReilInst(node.getInstruction());
			} catch (MLocException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			result = irsm.getRTable();
			
			
			long instLong = node.getInstruction().getAddress().toLong();
			if(heapChecker.eaxHeapMemoryCheck(instLong))
			{
				try {
					result = irsm.initEax2Heap();
				} catch (MLocException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			
			transformedState.setInst(node);
			transformedState.setRTable(result);			
			currentState.setRTable(result);
			return transformedState;
		}
	}
	
	public void printLoc(IStateVector<InstructionGraphNode, RTableLatticeElement> endVector){	 

		RTableLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 LogConsole.log("instruction : ");
			 LogConsole.log(inst.getInstruction().toString());
			 LogConsole.log("\n");
			 state.getRTable().printRTable();
		 }
	}
	public void deleteTempReg(IStateVector<InstructionGraphNode, RTableLatticeElement> endVector)
	{
		RTableLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 state.getRTable().deleteTempReg();
		 }
	}
	
	
}
