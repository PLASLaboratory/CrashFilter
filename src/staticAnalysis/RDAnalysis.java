package staticAnalysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.DefaultStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.IInfluencingState;
import com.google.security.zynamics.binnavi.API.reil.mono.ILattice;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeElement;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphEdge;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;
import crashfilter.va.MLocAnalysis.env.EnvLatticeElement;
import crashfilter.va.memlocations.MLocException;
import data.ReilInstructionResolve;
import helper.CrashSourceAdder;
import helper.InterProcedureMode;

public class RDAnalysis {
    private ILatticeGraph<InstructionGraphNode> graph;
    private IStateVector<InstructionGraphNode, RTableLatticeElement> locResult;
    private IStateVector<InstructionGraphNode, EnvLatticeElement> envResult;
    private Long crashAddr = null;
    private boolean monotoneChecker = true;;

    public RDAnalysis(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr) {
        this.graph = graph;
        this.crashAddr = crashAddr;
    }

    public void setLocResult(IStateVector<InstructionGraphNode, RTableLatticeElement> LocResult) {
        this.locResult = LocResult;
    }

    public void setEnvResult(IStateVector<InstructionGraphNode, EnvLatticeElement> envResult) {
        this.envResult = envResult;

    }

    public class RDLatticeElement implements ILatticeElement<RDLatticeElement> {

        private InstructionGraphNode inst;
        private Set<InstructionGraphNode> reachableInstList = new HashSet<InstructionGraphNode>();
        private Set<InstructionGraphNode> killList = new HashSet<InstructionGraphNode>();

        public void setInst(InstructionGraphNode inst) {
            this.inst = inst;
        }

        public InstructionGraphNode getInst() {
            return inst;
        }

        public Set<InstructionGraphNode> getReachableInstList() {
            return reachableInstList;
        }

        public Set<InstructionGraphNode> getKillList() {
            return killList;
        }

        public void unionReachableInstList(Set<InstructionGraphNode> state) {
            this.reachableInstList.addAll(state);
        }

        public void unionKillList(Set<InstructionGraphNode> killList) {
            this.killList.addAll(killList);
        }

        public void removeAllReachableInstList(Set<InstructionGraphNode> instList) {
            this.reachableInstList.removeAll(instList);
        }

        public void insertReachableInst(InstructionGraphNode inst) {
            this.reachableInstList.add(inst);
        }

        public void insertKill(InstructionGraphNode inst) {
            this.killList.add(inst);
        }

        public RDLatticeElement combine(List<RDLatticeElement> elements) {
            RDLatticeElement combinedElement = new RDLatticeElement();
            for (RDLatticeElement element : elements) {
                combinedElement.unionReachableInstList(element.getReachableInstList());
            }
            return combinedElement;
        }

        @Override
        public boolean equals(RDLatticeElement rhs) {
            if (rhs.getReachableInstList().containsAll(reachableInstList)) {
                if (reachableInstList.size() == rhs.getReachableInstList().size()) {
                    return true;
                }
            } else
                ; // error - it is not monotone
            return false;
        }

        @Override
        public boolean lessThan(RDLatticeElement rhs) {
            if (rhs.getReachableInstList().containsAll(reachableInstList)) {
                if (reachableInstList.size() < rhs.getReachableInstList().size()) {
                    return true;
                }

            } else
                ; // error - it is not monotone
            return false;
        }

    }

    // This function is used to combine states in each state positions of
    // program.
    public class RDLattice implements ILattice<RDLatticeElement, Object> {

        @Override
        public RDLatticeElement combine(List<IInfluencingState<RDLatticeElement, Object>> states) {
            RDLatticeElement combinedState = new RDLatticeElement();

            // Union all the predecessor's state
            for (IInfluencingState<RDLatticeElement, Object> state : states) {
                combinedState.unionReachableInstList(state.getElement().getReachableInstList());
            }

            return combinedState;
        }
    }

    public IStateVector<InstructionGraphNode, RDLatticeElement> initializeState(
            ILatticeGraph<InstructionGraphNode> graph) throws MLocException {

        RDLatticeElement state;
        IStateVector<InstructionGraphNode, RDLatticeElement> startVector = new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();

        // gathering the kill set of each instruction
        // After memory access analysis, we have to use the results.

        for (InstructionGraphNode defInst1 : graph.getNodes()) {
            state = new RDLatticeElement();
            for (InstructionGraphNode defInst2 : graph.getNodes()) {

                // Some time later we will add VSA and have to add some code for
                // new kill set considering memory
                if (ReilInstructionResolve.isSameDefinition(defInst1, defInst2)) {
                    state.insertKill(defInst2);
                }

            }
            startVector.setState(defInst1, state);
        }

        return startVector;
    }

    public IStateVector<InstructionGraphNode, RDLatticeElement> runRDAnalysis(InterProcedureMode analysisMode) throws MLocException {

        IStateVector<InstructionGraphNode, RDLatticeElement> startVector;
        IStateVector<InstructionGraphNode, RDLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();

        startVector = initializeState(graph);

        
        InstructionGraphNode crashSrcNode = CrashSourceAdder.getInstruction(graph, crashAddr, analysisMode);
        long toBeInsertedAddress = CrashSourceAdder.getNextReilAddrOfCrash(graph, crashAddr);

        
        
        Set< Map<InstructionGraphNode,Long>  > toBeAddedSrcNAddresses = new HashSet<>();

        toBeAddedSrcNAddresses = CrashSourceAdder.getSrcNAddress(graph, crashAddr, analysisMode);
 
        
        
        endVector = runRD(startVector, crashSrcNode, toBeInsertedAddress);
        return endVector;
    }

    private IStateVector<InstructionGraphNode, RDLatticeElement> runRD(
            IStateVector<InstructionGraphNode, RDLatticeElement> startVector, InstructionGraphNode crashSrcNode, long toBeInsertedAddress) {

        
        boolean changed = true;
        List<InstructionGraphNode> nodes = graph.getNodes();
        IStateVector<InstructionGraphNode, RDLatticeElement> vector = startVector;
        IStateVector<InstructionGraphNode, RDLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, RDLatticeElement>();

        while (changed) {
            for (InstructionGraphNode node : nodes) {
                List<InstructionGraphNode> preds = getPredNodes(node);

                if (hasNoPred(preds)) {
                    settingEntry(endVector, node);
                    continue;
                } else {
                    
                    RDLatticeElement transformedState = new RDLatticeElement();
                    RDLatticeElement currentState = applyMeetOperation(vector, node, preds, transformedState);
                    transferomState( node, transformedState, currentState);
                    
                    if (isInsertAddress(toBeInsertedAddress, node)) {
                        transformedState.insertReachableInst(crashSrcNode);
                    }
                    
                    endVector.setState(node, transformedState);
                }
            }

            changed = isChanged(vector, endVector);
            vector = endVector;
            System.out.println("chagned : " + changed);

        }

        return endVector;
    }

    private boolean isInsertAddress(long toBeInsertedAddress, InstructionGraphNode node) {
        return toBeInsertedAddress == node.getInstruction().getAddress().toLong();
    }

    private boolean isChanged(IStateVector<InstructionGraphNode, RDLatticeElement> vector,
            IStateVector<InstructionGraphNode, RDLatticeElement> endVector) {
        return !vector.equals(endVector);
    }

    private void transferomState( InstructionGraphNode node,   RDLatticeElement transformedState, RDLatticeElement currentState) {

        transformedState.removeAllReachableInstList(currentState.getKillList());

        if (!(ReilInstructionResolve.resolveReilInstructionDest(node).isEmpty())) {
            transformedState.insertReachableInst(node);
        }

        transformedState.unionKillList(currentState.getKillList());

     

        if (transformedState.lessThan(currentState)) {
            System.out.println("Error : RDAnalysis - runRD - lessThan");
        }
    }

    private RDLatticeElement applyMeetOperation(IStateVector<InstructionGraphNode, RDLatticeElement> vector,
            InstructionGraphNode node, List<InstructionGraphNode> preds, RDLatticeElement transformedState) {
        RDLatticeElement currentState = vector.getState(node);
        RDLatticeElement inputElement = unionPred(vector, preds);

        transformedState.unionReachableInstList(inputElement.getReachableInstList());
        return currentState;
    }

    private void settingEntry(IStateVector<InstructionGraphNode, RDLatticeElement> endVector,
            InstructionGraphNode node) {
        RDLatticeElement entry = new RDLatticeElement();
        entry.setInst(node);
        entry.reachableInstList = new HashSet<InstructionGraphNode>();
        entry.insertReachableInst(node);
        entry.inst = node;
        endVector.setState(node, entry);
    }

    private boolean hasNoPred(List<InstructionGraphNode> preds) {
        return preds.size() == 0;
    }

    private RDLatticeElement unionPred(IStateVector<InstructionGraphNode, RDLatticeElement> vector,
            List<InstructionGraphNode> preds) {
        if (hasNoPred(preds)) {
            return null;
        } else if (preds.size() == 1) {
            return vector.getState(preds.get(0));
        } else {
            RDLatticeElement mergedElement = new RDLatticeElement();
            List<RDLatticeElement> predElements = new ArrayList<RDLatticeElement>();
            for (InstructionGraphNode pred : preds) {
                predElements.add(vector.getState(pred));
            }
            return mergedElement.combine(predElements);
        }
    }

    private List<InstructionGraphNode> getPredNodes(InstructionGraphNode node) {
        List<InstructionGraphEdge> edges = node.getIncomingEdges();
        List<InstructionGraphNode> nodes = new ArrayList<InstructionGraphNode>();
        for (InstructionGraphEdge edge : edges) {
            nodes.add(edge.getSource());
        }
        return nodes;
    }

    public void printRD(IStateVector<InstructionGraphNode, RDLatticeElement> endVector) {

        RDLatticeElement state = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            state = endVector.getState(inst);
            LogConsole.log("instruction : ");
            LogConsole.log(inst.getInstruction().toString());
            LogConsole.log("\n");

            for (InstructionGraphNode reachingInst : state.getReachableInstList()) {
                LogConsole.log("\t" + reachingInst.getInstruction().toString());
                LogConsole.log("\n");
            }
        }
    }

}
