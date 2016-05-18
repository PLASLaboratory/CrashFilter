package staticAnalysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import com.google.security.zynamics.binnavi.API.reil.ReilFunction;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import data.ReilInstructionResolve;
import staticAnalysis.RDAnalysis.RDLatticeElement;

public class ReturnValueAnalysis implements TaintSink {
    private List<DefUseChain.DefUseGraph> duGraphs;
    private Function func;
    private Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> taintedReilPaths = new HashMap<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>>();
    private Map<Instruction, List<Instruction>> taintedArmPaths = new HashMap<Instruction, List<Instruction>>();

    private String crashAddr;

    private IStateVector<InstructionGraphNode, RDLatticeElement> RDResult;

    public ReturnValueAnalysis(List<DefUseChain.DefUseGraph> duGraphs, Function func, Long crashAddr,
            Map<String, String> crashFilteringResult, IStateVector<InstructionGraphNode, RDLatticeElement> RDResult) {
        this.duGraphs = duGraphs;
        this.func = func;
        this.RDResult = RDResult;
        this.crashAddr = Long.toHexString(crashAddr);
    }

    public Map<Instruction, List<Instruction>> getExploitArmPaths() {
        return taintedArmPaths;
    }

    public Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> getExploitReilPaths() {
        return taintedReilPaths;
    }

    private Instruction toArmInstruction(DefUseChain.DefUseNode duNode) {
        Instruction inst = ReilInstructionResolve.findNativeInstruction(func,
                ReilHelpers.toNativeAddress(duNode.getInst().getInstruction().getAddress()));

        return inst;
    }

    public void projectReilExploitToArmExploit() {
        for (DefUseChain.DefUseNode duNode : taintedReilPaths.keySet()) {

            Instruction exploitPoint = toArmInstruction(duNode);
            List<Instruction> armPath = new ArrayList<Instruction>();

            for (DefUseChain.DefUseNode node : taintedReilPaths.get(duNode)) {
                // LogConsole.log(node.getInst().toString()+"\n");
                Instruction armInst = toArmInstruction(node);
                if (!armPath.contains(armInst)) {
                    armPath.add(armInst);
                }
            }

            // Filtering the duplicated Path
            // It is because we analyze every each REIL instruction that is
            // translated from one ARM instuction
            if (taintedArmPaths.isEmpty()) {
                taintedArmPaths.put(exploitPoint, armPath);
            } else {
                boolean isContain = false;
                for (Instruction inst : taintedArmPaths.keySet()) {
                    if (taintedArmPaths.get(inst).containsAll(armPath)
                            && armPath.containsAll(taintedArmPaths.get(inst))) {
                        isContain = true;
                    }
                }
                if (!isContain) {
                    taintedArmPaths.put(exploitPoint, armPath);
                }
            }
        }
    }

    public boolean isTaintSink() {
        boolean isTaintSink = false;

        isTaintSink = isRetrunValueTainted();

        return isTaintSink;
    }

    private boolean isLastDefOfReturnValue(InstructionGraphNode inst) {
        if (RDResult == null) {
            System.out.println("error : RVA- isLastDefOfReturnValue()");
        }

        InstructionGraphNode lastInstruction = getLastInstruction(func);
        RDLatticeElement rdLatticeElement = RDResult.getState(lastInstruction);
        return isReachableToLastInstruction(inst, rdLatticeElement);
    }

    private boolean isReachableToLastInstruction(InstructionGraphNode inst, RDLatticeElement rdLatticeElement) {
        return rdLatticeElement.getReachableInstList().contains(inst);
    }

    private InstructionGraphNode getLastInstruction(Function func) {

        InstructionGraph graph = transformGraph(func);

        InstructionGraphNode lastInst = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            lastInst = inst;
        }

        return lastInst;

    }

    private InstructionGraph transformGraph(Function func) {
        ReilFunction curReilFunc = null;
        try {
            curReilFunc = func.getReilCode();
        } catch (InternalTranslationException e) {
            e.printStackTrace();
        }

        InstructionGraph graph = InstructionGraph.create(curReilFunc.getGraph());
        return graph;
    }

    private boolean isRetrunValueTainted() {

        searchTaintedRetrunValue();
        projectReilExploitToArmExploit();
        if (taintedReilPaths.isEmpty()) {
            return false;
        }

        return true;
    }

    private boolean isDefUsedInAddressToBranch(InstructionGraphNode use, InstructionGraphNode def) {
        if (hasRegisterThirdOperation(use)) {
            for (ReilOperand op : ReilInstructionResolve.resolveReilInstructionDest(def)) {
                if (use.getInstruction().getThirdOperand().getValue().equals(op.getValue())) {
                    return true;
                }
            }
            return false;
        } else
            return false;

    }

    private boolean isTaintedReturnValue(DefUseChain.DefUseNode node) {

        ReilInstruction inst = node.getInst().getInstruction();

        if (isBinaryOperation(inst)) {
            return false;
        } else {
            if (isLastDefOfReturnValue(node.getInst())) {
                return isDefRetrunVauleWithTaint(node.getInst());
            }
        }
        return false;

    }

    private boolean isDefRetrunVauleWithTaint(InstructionGraphNode def) {
        // TODO
        return (def.getInstruction().getThirdOperand().getValue().equals("eax")
                || def.getInstruction().getThirdOperand().getValue().equals("r0"));
    }

    private boolean hasRegisterThirdOperation(InstructionGraphNode use) {
        return ReilHelpers.isRegister(use.getInstruction().getThirdOperand());
    }

    private boolean isBinaryOperation(ReilInstruction inst) {
        return inst.getMnemonic().equals("add") || inst.getMnemonic().equals("sub") || inst.getMnemonic().equals("mul")
                || inst.getMnemonic().equals("div") || inst.getMnemonic().equals("mod")
                || inst.getMnemonic().equals("xor") || inst.getMnemonic().equals("or")
                || inst.getMnemonic().equals("and") || inst.getMnemonic().equals("bsh");
    }

    private void searchTaintedRetrunValue() {
        // All the graphs is analyzed at this function

        for (DefUseChain.DefUseGraph duGraph : duGraphs) {
            Stack<DefUseChain.DefUseNode> stackDFS = new Stack<DefUseChain.DefUseNode>();
            Set<DefUseChain.DefUseNode> visitedNodes = new HashSet<DefUseChain.DefUseNode>();

            // We find all possible exploitable instruction in this function
            // We consider the possibility in detail after this process
            // Depth First Search Algorithm

            System.out.println("search : " + duGraph.getNodes().get(0));
            searchTaintRetrunValueDFS(stackDFS, visitedNodes, duGraph.getNodes().get(0));
        }

        printResultOnLog();

    }

    private void printResultOnLog() {
        System.out.println(" I have nothing to tell..");
    }

    private void searchTaintRetrunValueDFS(Stack<DefUseChain.DefUseNode> stackDFS,
            Set<DefUseChain.DefUseNode> visitedNode, DefUseChain.DefUseNode duNode) {

        // current node processing
        visitedNode.add(duNode);
        stackDFS.push(duNode);
        if (isTaintedReturnValue(duNode)) {
            List<DefUseChain.DefUseNode> exploitPath = new ArrayList<DefUseChain.DefUseNode>();
            exploitPath.addAll(stackDFS);
            taintedReilPaths.put(duNode, exploitPath);
        }

        // children iteration
        searchChildren(stackDFS, visitedNode, duNode);
        stackDFS.pop();
    }

    private void searchChildren(Stack<DefUseChain.DefUseNode> stackDFS, Set<DefUseChain.DefUseNode> visitedNode,
            DefUseChain.DefUseNode duNode) {
        for (DefUseChain.DefUseNode node : duNode.getChildren()) {
            if (!visitedNode.contains(node)) {
                searchTaintRetrunValueDFS(stackDFS, visitedNode, node);
            }
        }
    }

    @Override
    public int getTotal_e_count() {
        return 0;
    }

    @Override
    public int getTotal_pe_count() {
        return 0;
    }

}
