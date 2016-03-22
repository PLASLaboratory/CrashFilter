package crashfilter.va.MLocAnalysis;

import java.util.List;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.DefaultStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.DownWalker;
import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.ITransformationProvider;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import com.google.security.zynamics.binnavi.API.reil.mono.MonotoneSolver;
import com.google.security.zynamics.binnavi.Debug.Connection.Packets.A.r;

import crashfilter.va.MLocAnalysis.RTable.IRSetManager;
import crashfilter.va.MLocAnalysis.RTable.RTable;
import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;
import crashfilter.va.MLocAnalysis.env.Env;
import crashfilter.va.MLocAnalysis.env.EnvLattice;
import crashfilter.va.MLocAnalysis.env.EnvLatticeElement;
import crashfilter.va.MLocAnalysis.env.EnvManager;
import crashfilter.va.memlocations.MLocException;
import helper.CallStackCleaner;
import helper.HeapChecker;
import staticAnalysis.EnvAnalysis.EnvTransferFunction;

public class MLocAnalysis {
	private ILatticeGraph<InstructionGraphNode> graph;
	private Function function;
	private HeapChecker heapChecker;
	private int count=0;
	public MLocAnalysis( ILatticeGraph<InstructionGraphNode> graph, Function function ){
		this.graph = graph;
		this.function = function;
		heapChecker = HeapChecker.initHeapChecker(graph, function);
	}
	public IStateVector<InstructionGraphNode, MLocLatticeElement> mLocAnalysis() throws MLocException
	{
		MLocLattice lattice;
		IStateVector<InstructionGraphNode, MLocLatticeElement> startVector;
		IStateVector<InstructionGraphNode, MLocLatticeElement> endVector;
		 
		ITransformationProvider<InstructionGraphNode, MLocLatticeElement> transferFunction;
		DownWalker<InstructionGraphNode> walker;
		MonotoneSolver<InstructionGraphNode, MLocLatticeElement, Object, MLocLattice> solver;

		lattice = new MLocLattice();
		 
		startVector = initializeState(graph);
		transferFunction = new MLocTransferFunction();
		walker = new DownWalker<InstructionGraphNode>();

		solver = new MonotoneSolver<InstructionGraphNode, MLocLatticeElement, Object, MLocLattice>( graph, lattice, startVector, transferFunction, walker );
		endVector = solver.solve();
		return endVector;
	}
	 
	
	private IStateVector<InstructionGraphNode, MLocLatticeElement> initializeState(	ILatticeGraph<InstructionGraphNode> inputGraph) throws MLocException {
	
		IStateVector<InstructionGraphNode, MLocLatticeElement> startVector =  new DefaultStateVector<InstructionGraphNode, MLocLatticeElement>();
		
		heapChecker.findHeapAllocation(function);
		
		List<InstructionGraphNode> instList = inputGraph.getNodes();
		MLocLatticeElement state ;
		
		for (InstructionGraphNode inst : graph.getNodes()){
			
			state = new MLocLatticeElement();
			
			RTable initializedRTable = initRTable();			
			Env initializedEnv = initEnv();
			
			state.setInst(inst);
			state.setRTable(initializedRTable);
			state.setEnv(initializedEnv);
			
			startVector.setState(inst, state);
		}
		return startVector;
	}
	private RTable initRTable() throws MLocException
	{
		RTable rTable = new RTable();
		IRSetManager irsm = IRSetManager.getIRSetManager();
		irsm.setRTable(rTable);
		

		rTable = irsm.initFirst();			
		//rTable = irsm.init();
		return rTable;
	}
	private Env initEnv() throws MLocException
	{
		Env env = new Env();
		EnvManager eManager = EnvManager.getEnvManager();
		eManager.setEnv(env);			

		//env = eManager.initFirst();			
		env = eManager.init();
		return env;
	}
	
	
	public class MLocTransferFunction implements ITransformationProvider<InstructionGraphNode, MLocLatticeElement>{
		@Override
		public MLocLatticeElement transform(
				InstructionGraphNode node,
				MLocLatticeElement currentState,
				MLocLatticeElement inputState
				) {
			MLocLatticeElement transformedState = new MLocLatticeElement();
			Env inputEnv = inputState.getEnv();
			Env currentEnv = currentState.getEnv();
			Env transformed_Env;
			
			if(inputEnv == null)
			{
				transformed_Env = currentEnv;
			}
			else
			{
				if(inputEnv.size() == 0)
				{
					transformed_Env = currentEnv;
				}
				else
				{
					transformed_Env = inputEnv;
				}
			}
			
			RTable inputRTable = inputState.getRTable();
			RTable currentRTable = currentState.getRTable();
			
			RTable transformed_RTable;
			if(inputRTable == null )
			{
				transformed_RTable = currentRTable;
			}
			else
			{
				if(inputRTable.size() == 0)
				{
					transformed_RTable = currentRTable;
				}
				else
				{
					transformed_RTable = inputRTable;
				}
				
			}
			
			IRSetManager rTableManager = IRSetManager.getIRSetManager();
			rTableManager.setEnv(transformed_Env);
			rTableManager.setRTable(transformed_RTable);
			
			//trnasfer 
			CallStackCleaner callStackCleaner = CallStackCleaner.getCallStackCleaner();
			if(callStackCleaner.isToBeClearedStack(node))
			{
				System.out.println("call stack cleaning...");
				callStackCleaner.clearCallStack_Ebp(transformed_RTable, transformed_Env);
			}
			
			try {
				rTableManager.oneReilInst(node.getInstruction());
			} catch (MLocException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			
			//state setting
			inputRTable = transformed_RTable;
			currentRTable = transformed_RTable;
			currentState.setRTable(transformed_RTable);			
			
			inputEnv = transformed_Env;
			currentEnv = transformed_Env;
			currentState.setEnv(transformed_Env);
			
			
			
			transformedState.setInst(node);
			transformedState.setEnv(transformed_Env);
			transformedState.setRTable(transformed_RTable);

			return transformedState;
		}
	}
	public void deleteTempReg(IStateVector<InstructionGraphNode, MLocLatticeElement> endVector)
	{
		MLocLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 state.getRTable().deleteTempReg();
			 state.getEnv().deleteTempReg();
		 }
	}
	public void deleteBottomSymbol(IStateVector<InstructionGraphNode, MLocLatticeElement> vector)
	{
		MLocLatticeElement state = null;
		for( InstructionGraphNode inst : graph.getNodes() ){
			 state = vector.getState(inst);
			 state.getEnv().deleteNullNBottom();
			 state.getRTable().deleteNullNBottom();
		}
	}
	//private
}
