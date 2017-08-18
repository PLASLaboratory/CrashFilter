package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.*;
import plugin.java.com.plas.crashfilter.analysis.helper.CrashSourceAdder;
import plugin.java.com.plas.crashfilter.analysis.helper.VariableFinder;
import plugin.java.com.plas.crashfilter.analysis.ipa.InterProcedureMode;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;

import java.util.*;

public class ReachingDefinition {
    private ILatticeGraph<InstructionGraphNode> graph;
    
    
    private Long crashAddr = null;
    private VariableFinder vf;

    public ReachingDefinition(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr, VariableFinder vf) {
        this.graph = graph;
        this.crashAddr = crashAddr;
        this.vf = vf;
    }


    public IStateVector<InstructionGraphNode, DefLatticeElement> initializeState(
            ILatticeGraph<InstructionGraphNode> graph) throws MLocException {
        //초기 상태 초기화
        //초기 상태는 empty set으로 시작하기 때문에 kill set 외에 따로 초기화 하지 않음
        DefLatticeElement state;
        IStateVector<InstructionGraphNode, DefLatticeElement> startVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

        // gathering the kill set of each instruction
        // After memory access analysis, we have to use the results.

        for (InstructionGraphNode defInst1 : graph.getNodes()) {
            state = new DefLatticeElement();
            for (InstructionGraphNode defInst2 : graph.getNodes()) {
                //킬셋 초기화
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

    public IStateVector<InstructionGraphNode, DefLatticeElement> runRDAnalysis(InterProcedureMode analysisMode) throws MLocException {

        IStateVector<InstructionGraphNode, DefLatticeElement> startVector;
        IStateVector<InstructionGraphNode, DefLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

        startVector = initializeState(graph);

        
        Map<Long, InstructionGraphNode> toBeAddedSrcNAddresses = new HashMap<Long, InstructionGraphNode>();
        toBeAddedSrcNAddresses = CrashSourceAdder.getSrcNAddress(graph, crashAddr, analysisMode, vf);
 
   
        endVector = runRD(startVector, toBeAddedSrcNAddresses);
        return endVector;
    }

    private IStateVector<InstructionGraphNode, DefLatticeElement> runRD(
            IStateVector<InstructionGraphNode, DefLatticeElement> startVector, Map<Long, InstructionGraphNode> toBeAddedSrcNAddresses) {

        
        boolean changed = true;
        List<InstructionGraphNode> nodes = graph.getNodes();
        IStateVector<InstructionGraphNode, DefLatticeElement> vector = startVector;
        IStateVector<InstructionGraphNode, DefLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

        while (changed) {
            for (InstructionGraphNode node : nodes) {
                List<InstructionGraphNode> preds = getPredNodes(node);

                if (hasNoPred(preds)) {
                    settingEntry(endVector, node);
                } else {
                    
                    DefLatticeElement transformedState = new DefLatticeElement();

                    //meet operation
                    //To do: currentSate 이름 바꾸기==>inState by 성균
                    //
                    DefLatticeElement currentState = applyMeetOperation(vector, node, preds, transformedState);
                    //

                    //transfer function
                    //binnavi의 인터페이스보고 같은 형태로 되게 하기
                    //IN: transformState
                    //currentState: instList는 previous out, KILLList는 KILL
                    transformState( node, transformedState, currentState);

                    //이 부분 내가 아직 잘 모름
                    //교수님 추측: IPA에서 쓰는 것이 아닐까
                    if (isInsertAddress(toBeAddedSrcNAddresses, node)) {
                        InstructionGraphNode srcNode = toBeAddedSrcNAddresses.get(node.getInstruction().getAddress().toLong());
                        transformedState.insertInst(srcNode);
                    }
                    
                    endVector.setState(node, transformedState);
                }
            }

            changed = isChanged(vector, endVector);
            vector = endVector;
            System.out.println("changed : " + changed);

        }

        return endVector;
    }

    private boolean isInsertAddress(Map<Long, InstructionGraphNode> toBeAddedSrcNAddresses, InstructionGraphNode node) {
        return toBeAddedSrcNAddresses.containsKey(node.getInstruction().getAddress().toLong());
    }

    private boolean isChanged(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
            IStateVector<InstructionGraphNode, DefLatticeElement> endVector) {
        return !vector.equals(endVector);
    }

    private void transformState(InstructionGraphNode node, DefLatticeElement transformedState, DefLatticeElement currentState) {
        //transformedState = IN - KILL
        transformedState.removeAllInstList(currentState.getKillList());

        //transformedState = (IN- KILL) + GEN
        if (!(ReilInstructionResolve.resolveReilInstructionDest(node).isEmpty())) {

            transformedState.insertInst(node);
        }
        //new transformedState의 KILL 초기화
        transformedState.unionKillList(currentState.getKillList());

     
        //라티스 fixed point 성질 확인
        if (transformedState.lessThan(currentState)) {
            System.out.println("Error : ReachingDefinition - runRD - lessThan");
        }
    }

    private DefLatticeElement applyMeetOperation(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
                                                 InstructionGraphNode node, List<InstructionGraphNode> preds, DefLatticeElement transformedState) {
        DefLatticeElement currentState = vector.getState(node);
        //변수이름 바꾸기
        //
        DefLatticeElement inputElement = unionPred(vector, preds);

        transformedState.unionInstList(inputElement.getInstList());
        return currentState;
    }

    private void settingEntry(IStateVector<InstructionGraphNode, DefLatticeElement> endVector,
            InstructionGraphNode node) {
        DefLatticeElement entry = new DefLatticeElement();
        entry.setInst(node);
        entry.instList = new HashSet<InstructionGraphNode>();
        entry.insertInst(node);
        entry.inst = node;
        endVector.setState(node, entry);
    }

    private boolean hasNoPred(List<InstructionGraphNode> preds) {
        return preds.size() == 0;
    }

    private DefLatticeElement unionPred(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
                                        List<InstructionGraphNode> preds) {
        if (hasNoPred(preds)) {
            return null;
        } else if (preds.size() == 1) {
            return vector.getState(preds.get(0));
        } else {
            DefLatticeElement mergedElement = new DefLatticeElement();
            List<DefLatticeElement> predElements = new ArrayList<DefLatticeElement>();
            for (InstructionGraphNode pred : preds) {
                predElements.add(vector.getState(pred));
            }
            return mergedElement.transLatticeElement(predElements);
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

    public void printRD(IStateVector<InstructionGraphNode, DefLatticeElement> endVector) {

        DefLatticeElement state = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            state = endVector.getState(inst);
            LogConsole.log("instruction : ");
            LogConsole.log(inst.getInstruction().toString());
            LogConsole.log("\n");

            for (InstructionGraphNode reachingInst : state.getInstList()) {
                LogConsole.log("\t" + reachingInst.getInstruction().toString());
                LogConsole.log("\n");
            }
        }
    }

}
