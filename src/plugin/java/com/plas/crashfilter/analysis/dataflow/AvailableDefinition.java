
package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.common.collect.Sets;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.mono.*;
import plugin.java.com.plas.crashfilter.analysis.helper.CrashSourceAdder;
import plugin.java.com.plas.crashfilter.analysis.helper.VariableFinder;
import plugin.java.com.plas.crashfilter.analysis.ipa.InterProcedureMode;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;

import java.util.*;

public class AvailableDefinition {
    private ILatticeGraph<InstructionGraphNode> graph;



    private Long crashAddr = null;
    private VariableFinder vf;

    public AvailableDefinition(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr, VariableFinder vf) {
        this.graph = graph;
        this.crashAddr = crashAddr;
        this.vf = vf;
    }

    public IStateVector<InstructionGraphNode, DefLatticeElement> initDef(ILatticeGraph<InstructionGraphNode> graph){
        IStateVector<InstructionGraphNode, DefLatticeElement> defSet = new DefaultStateVector<>();

        for(InstructionGraphNode defInst : graph.getNodes()){
           if(ReilInstructionResolve.isDefinitionInstruction(defInst)){
               DefLatticeElement state = new DefLatticeElement();
               state.insertInst(defInst);
               defSet.setState(defInst, state);
           }
        }
        return defSet;
    }


    public IStateVector<InstructionGraphNode, DefLatticeElement> initializeState(
            ILatticeGraph<InstructionGraphNode> graph) throws MLocException {
        //kill과 초기 state 초기화
        //초기 state는 자기 자신의 def
        DefLatticeElement state;
        IStateVector<InstructionGraphNode, DefLatticeElement> startVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

        // gathering the kill set of each instruction
        // After memory access analysis, we have to use the results.
    //def collection 지역변수로 받기
        for (InstructionGraphNode defInst1 : graph.getNodes()) {
            state = new DefLatticeElement();

            //초기치 지정하는 것 available일 때는 전체 def 집합,
            //리칭 데피니션에서는 공집합
            //state.insertInstAll(def collection 받아논 것이 인자)
            state.insertInst(defInst1);

            //kill set 채우는 것
            //나중에 함수로 빼고,
            state.insertInstAll(graph.getNodes());
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

    public IStateVector<InstructionGraphNode, DefLatticeElement> runADAnalysis(InterProcedureMode analysisMode) throws MLocException {

        IStateVector<InstructionGraphNode, DefLatticeElement> startVector;
        IStateVector<InstructionGraphNode, DefLatticeElement> endVector = new DefaultStateVector<InstructionGraphNode, DefLatticeElement>();

        //startVector 초기화
        startVector = initializeState(graph);
        Map<Long, InstructionGraphNode> toBeAddedSrcNAddresses = new HashMap<Long, InstructionGraphNode>();
        toBeAddedSrcNAddresses = CrashSourceAdder.getSrcNAddress(graph, crashAddr, analysisMode, vf);
        endVector = runAD(startVector, toBeAddedSrcNAddresses);
        return endVector;
    }

    private IStateVector<InstructionGraphNode, DefLatticeElement> runAD(
            IStateVector<InstructionGraphNode, DefLatticeElement> startVector, Map<Long, InstructionGraphNode> toBeAddedSrcNAddresses) {

        LogConsole.log("==========Available Definition analysis start!!!!!!\n");
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
                    DefLatticeElement currentState = applyMeetOperation(vector, node, preds, transformedState);
                    transformState( node, transformedState, currentState);

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
        //enum으로 flag 정의하고, RD
        transformedState.removeAllInstList(currentState.getKillList());

        if (!(ReilInstructionResolve.resolveReilInstructionDest(node).isEmpty())) {
            transformedState.insertInst(node);
        }

        transformedState.unionKillList(currentState.getKillList());
        if (transformedState.greaterThan(currentState)) {
            //lessThan 반대로 바꾸기
            System.out.println("Error : Available Definition - runAD - greaterThan");
        }
    }

    private DefLatticeElement applyMeetOperation(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
                                                 InstructionGraphNode node, List<InstructionGraphNode> preds, DefLatticeElement transformedState) {
        DefLatticeElement currentState = vector.getState(node);
        DefLatticeElement inputElement = intersectPred(vector, preds);


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
            return mergedElement.combineIntersect(predElements);
        }
    }
    private DefLatticeElement intersectPred(IStateVector<InstructionGraphNode, DefLatticeElement> vector,
                                        List<InstructionGraphNode> preds) {
        if (hasNoPred(preds)) {
            return null;
        } else if (preds.size() == 1) {
            return vector.getState(preds.get(0));
        } else {
            DefLatticeElement mergedElement = new DefLatticeElement();
            Set<InstructionGraphNode> resultSet = null;
            for (InstructionGraphNode pred : preds) {
                if(resultSet == null)
                    resultSet = vector.getState(pred).getInstList();
                else {
                    resultSet = Sets.intersection(resultSet, vector.getState(pred).getInstList());

                }
            }
            mergedElement.instList = resultSet;
            return mergedElement;
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

    public void printAD(IStateVector<InstructionGraphNode, DefLatticeElement> endVector) {

        DefLatticeElement state = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            state = endVector.getState(inst);
            LogConsole.log("instruction : ");
            LogConsole.log(inst.getInstruction().toString());
            LogConsole.log("\n");

            for (InstructionGraphNode availableInst : state.getInstList()) {
                LogConsole.log("\t" + availableInst.getInstruction().toString());
                LogConsole.log("\n");
            }
        }
    }

}
