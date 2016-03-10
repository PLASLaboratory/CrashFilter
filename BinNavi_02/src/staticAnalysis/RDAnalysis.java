package staticAnalysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.DefaultStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.DownWalker;
import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeElement;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.ITransformationProvider;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphEdge;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import com.google.security.zynamics.binnavi.API.reil.mono.MonotoneSolver;

import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;
import crashfilter.va.MLocAnalysis.env.EnvLatticeElement;
import crashfilter.va.memlocations.MLocException;
import data.ReilInstructionResolve;
import helper.CrashSourceAdder;

public class RDAnalysis {
	private ILatticeGraph<InstructionGraphNode> graph;
	IStateVector<InstructionGraphNode, RTableLatticeElement> locResult;
	IStateVector<InstructionGraphNode, EnvLatticeElement> envResult;
	Long crashAddr  =null;
	boolean monotoneChecker = true;;
	
	public RDAnalysis( ILatticeGraph<InstructionGraphNode> graph , Long crashAddr){
		this.graph = graph;
		this.crashAddr = crashAddr;		
	}
	public void setLocResult(IStateVector<InstructionGraphNode, RTableLatticeElement> LocResult)
	{
		this.locResult = LocResult;	
	}
	public void setEnvResult(
			IStateVector<InstructionGraphNode, EnvLatticeElement> envResult) {
		this.envResult = envResult;
		
	}
	public class RDLatticeElement implements ILatticeElement<RDLatticeElement>{
		
		private InstructionGraphNode inst;
		private Set<InstructionGraphNode> instList = new HashSet<InstructionGraphNode>();
		private Set<InstructionGraphNode> killList = new HashSet<InstructionGraphNode>();
		
		public void setInst( InstructionGraphNode inst){
			this.inst = inst;
		}
		public InstructionGraphNode getInst(){
			return inst;
		}
		public Set<InstructionGraphNode> getInstList( ){
			return instList;
		}
		
		public Set<InstructionGraphNode> getKillList( ){
			return killList;
		}
		
		public void unionInstList(Set<InstructionGraphNode> state){
			this.instList.addAll(state);
		}
		
		public void unionKillList(Set<InstructionGraphNode> killList){
			this.killList.addAll(killList);
		}
		
		public void removeAllInstList(Set<InstructionGraphNode> instList){
			this.instList.removeAll(instList);
		}
		
		public void insertInst(InstructionGraphNode inst){
			this.instList.add(inst);
		}
		
		public void insertKill(InstructionGraphNode inst){
			this.killList.add(inst);
		}
		
		public RDLatticeElement combine(List<RDLatticeElement> elements)
		{
			RDLatticeElement combinedElement = new RDLatticeElement();
			for(RDLatticeElement element : elements)
			{
				combinedElement.unionInstList(element.getInstList());
			}
			return combinedElement;			
		}
		@Override
		public boolean equals(RDLatticeElement rhs) {
			if(rhs.getInstList().containsAll(instList)){
				if(instList.size() == rhs.getInstList().size())
				{
					return true;
				}
			}
			else
				; //error - it is not monotone
			return false;
		}

		@Override
		public boolean lessThan(RDLatticeElement rhs) {
			if(rhs.getInstList().containsAll(instList)){
				if(instList.size() < rhs.getInstList().size())
				{
					return true;
				}
				
			}
			else
				; //error - it is not monotone
			return false;
		}
		
		

	}
	
	//This function is used to combine states in each state positions of program.
	public class RDLattice implements ILattice<RDLatticeElement, Object>{
		 
		@Override
		public RDLatticeElement combine( List<IInfluencingState<RDLatticeElement, Object>> states ) {
			RDLatticeElement combinedState = new RDLatticeElement();
			
			//Union all the predecessor's state
			for ( IInfluencingState<RDLatticeElement, Object> state : states ){
				combinedState.unionInstList(state.getElement().getInstList());				
			}
			
			return combinedState;
		}
	}
	
	public class RDTransferFunction implements ITransformationProvider<InstructionGraphNode, RDLatticeElement>{
		@Override
		public RDLatticeElement transform(
				InstructionGraphNode node,
				RDLatticeElement currentState,
				RDLatticeElement inputState
				) {

			
			//each InstructionGraphNodes like LDM and STM, we can resolve the memory access operand using value-set analysis result
			RDLatticeElement transformedState = new RDLatticeElement();
						

			transformedState.unionInstList(inputState.getInstList());
			transformedState.removeAllInstList(currentState.getKillList());
			
			if(!(ReilInstructionResolve.resolveReilInstructionDest(node).isEmpty())){			
				transformedState.insertInst(node);
			}
			
			
			transformedState.unionKillList(currentState.getKillList());
			
			return transformedState;
		}
	}
	
	

	
	public  IStateVector<InstructionGraphNode, RDLatticeElement> initializeState(ILatticeGraph<InstructionGraphNode> graph) throws MLocException{
		
		 RDLatticeElement state;
		 IStateVector<InstructionGraphNode, RDLatticeElement> startVector = 
				 new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();
		 
		 //gathering the kill set of each instruction 
		 //After memory access analysis, we have to use the results.
		 
		 List<InstructionGraphNode> insts = CrashSourceAdder.getInstructionlist( graph, crashAddr);
		 InstructionGraphNode srcNode = CrashSourceAdder.getInstruction(graph, crashAddr);
	
		 
		 for (InstructionGraphNode defInst1 :  graph.getNodes()){
			 state = new RDLatticeElement();
			 for (InstructionGraphNode defInst2 : graph.getNodes()){

				 //Some time later we will add VSA and have to add some code for new kill set considering memory
				 if(ReilInstructionResolve.isSameDefinition(defInst1, defInst2)){
					 state.insertKill(defInst2);
				 }
	 
				
			 }
			 startVector.setState(defInst1, state);
		 }

		return startVector;
	}


	public IStateVector<InstructionGraphNode, RDLatticeElement> reachingDefinitionAnalysis() throws MLocException {
//		 MessageBox.showInformation(null, "MenuPlugin test!!");
		 RDLattice lattice;
		 IStateVector<InstructionGraphNode, RDLatticeElement> startVector;
		 IStateVector<InstructionGraphNode, RDLatticeElement> endVector;
		 
		 ITransformationProvider<InstructionGraphNode, RDLatticeElement> transferFunction;
		 DownWalker<InstructionGraphNode> walker;
		 MonotoneSolver<InstructionGraphNode, RDLatticeElement, Object, RDLattice> solver;


		 lattice = new RDLattice();
		 
		 startVector = initializeState(graph);
		 transferFunction = new RDTransferFunction();
		 walker = new DownWalker<InstructionGraphNode>();
		 solver = new MonotoneSolver<InstructionGraphNode, RDLatticeElement, Object, RDLattice>(
				 graph, lattice, startVector, transferFunction, walker
				 );
		 

		 return endVector = solver.solve();			 
	}
	
	public IStateVector<InstructionGraphNode, RDLatticeElement> RDAnalysis() throws MLocException{
		RDLattice lattice;
		IStateVector<InstructionGraphNode, RDLatticeElement> startVector;
		IStateVector<InstructionGraphNode, RDLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();
		 
		ITransformationProvider<InstructionGraphNode, RDLatticeElement> transferFunction;
		
		lattice = new RDLattice();
		 
		startVector = initializeState(graph);
		
				
		endVector = runRD(startVector);
		return endVector;
	}
	
	private IStateVector<InstructionGraphNode, RDLatticeElement> runRD(
			IStateVector<InstructionGraphNode, RDLatticeElement> startVector) {
		
		
		InstructionGraphNode crashSrcNode = CrashSourceAdder.getInstruction(graph, crashAddr);
		long nextAddrOfCrash = CrashSourceAdder.getNextAddrOfCrash(graph, crashAddr);
		
		
		boolean changed = true;
		List<InstructionGraphNode> nodes = graph.getNodes();
		IStateVector<InstructionGraphNode, RDLatticeElement> vector = startVector;
		IStateVector<InstructionGraphNode, RDLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();
		
		
		
		while(changed)
		{
			for(InstructionGraphNode node : nodes)
			{
				List<InstructionGraphNode> preds = getPredNodes(node);
				
				if(preds.size() ==0)
				{
					RDLatticeElement entry = new RDLatticeElement();
					entry.setInst(node);
					entry.instList = new HashSet<InstructionGraphNode>();
					entry.insertInst(node);
					entry.inst = node;
					endVector.setState(node, entry);
					continue;
				}			
				else
				{
					//transform					
					//meet operation U
					RDLatticeElement inputElement = unionPred(vector, preds);
					RDLatticeElement currentState = vector.getState(node);
					
					RDLatticeElement transformedState = new RDLatticeElement();
					
					
					transformedState.unionInstList(inputElement.getInstList());					
					
					transformedState.removeAllInstList(currentState.getKillList());							
					if(!(ReilInstructionResolve.resolveReilInstructionDest(node).isEmpty())){			
						transformedState.insertInst(node);
					}
					
					transformedState.unionKillList(currentState.getKillList());
				
					if(nextAddrOfCrash == node.getInstruction().getAddress().toLong())
					{
						transformedState.insertInst(crashSrcNode);
					}
					
					
					if(transformedState.lessThan(currentState))
					{
						System.out.println("Error : lessssssss");
					}
					endVector.setState(node, transformedState);				
				}
			}
			
			changed = !vector.equals(endVector);
			vector = endVector;
			System.out.println("chagned : "+changed);
			
		}
		
		return endVector;
	}
	
	private RDLatticeElement unionPred(IStateVector<InstructionGraphNode, RDLatticeElement> vector, List<InstructionGraphNode> preds)
	{
		if(preds.size() ==0 )
		{
			return null;
		}
		else if(preds.size() == 1 )
		{
			return vector.getState(preds.get(0));
		}
		else
		{
			RDLatticeElement mergedElement = new RDLatticeElement();
			List<RDLatticeElement> predElements = new ArrayList<RDLatticeElement>();
			for(InstructionGraphNode pred : preds)
			{
				predElements.add(vector.getState(pred));
			}
			return mergedElement.combine(predElements);			
		}
	}
	private List<InstructionGraphNode> getPredNodes(InstructionGraphNode node)
	{
		List<InstructionGraphEdge> edges = node.getIncomingEdges();
		List<InstructionGraphNode> nodes = new ArrayList<InstructionGraphNode>();
		for(InstructionGraphEdge edge : edges)
		{
			nodes.add(edge.getSource());
		}
		return nodes;
	}
	
	public void printRD(IStateVector<InstructionGraphNode, RDLatticeElement> endVector){	 
		
		RDLatticeElement state = null;
		 for( InstructionGraphNode inst : graph.getNodes() ){
			 state = endVector.getState(inst);
			 LogConsole.log("instruction : ");
			 LogConsole.log(inst.getInstruction().toString());
			 LogConsole.log("\n");
		 
			 for( InstructionGraphNode reachingInst : state.getInstList()){
				 LogConsole.log("\t" + reachingInst.getInstruction().toString());
				 LogConsole.log("\n");
			 }
		 }
	}
	
}
