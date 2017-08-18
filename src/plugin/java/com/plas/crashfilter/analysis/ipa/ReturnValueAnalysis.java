package plugin.java.com.plas.crashfilter.analysis.ipa;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefLatticeElement;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefUseChain;
import plugin.java.com.plas.crashfilter.analysis.helper.Dangerousness;
import plugin.java.com.plas.crashfilter.analysis.helper.TaintSink;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;

import java.util.*;

public class ReturnValueAnalysis implements TaintSink {
    private IStateVector<InstructionGraphNode, DefLatticeElement> RDResult;
    private List<DefUseChain.DefUseGraph> duGraphs;
    private Function func;
    private Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> taintedReilPaths = new HashMap<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>>();
    private Map<Instruction, List<Instruction>> taintedArmPaths = new HashMap<Instruction, List<Instruction>>();

    private Dangerousness dnagerousness = Dangerousness.NE;

    public Dangerousness getDnagerousness() {
        return dnagerousness;
    }

    private ILatticeGraph<InstructionGraphNode> graph;

    public ReturnValueAnalysis(List<DefUseChain.DefUseGraph> duGraphs, Function func,
                               Map<Long, Dangerousness> crashFilteringResult,
                               IStateVector<InstructionGraphNode, DefLatticeElement> RDResult, ILatticeGraph<InstructionGraphNode> graph) {
        this.duGraphs = duGraphs;
        this.func = func;
        this.RDResult = RDResult;
        this.graph = graph;
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

    public boolean isTaintSink() {
        boolean isTaintSink = false;

        isTaintSink = isRetrunValueTainted();

        return isTaintSink;
    }

    private boolean isReachableAtReturn(InstructionGraphNode inst) {
        if (RDResult == null) {
            System.out.println("error : RVA- isLastDefOfReturnValue()");
        }

        InstructionGraphNode lastInstruction = getLastInstruction(func);

        DefLatticeElement defLatticeElement = RDResult.getState(lastInstruction);
        if (defLatticeElement == null) {
            System.out.println("DefLatticeElement is null");
            System.exit(-1);
        }

        return isReachableToLastInstruction(inst, defLatticeElement);
    }

    private boolean isReachableToLastInstruction(InstructionGraphNode inst, DefLatticeElement defLatticeElement) {
        return defLatticeElement.getInstList().contains(inst);
    }

    private InstructionGraphNode getLastInstruction(Function func) {

        InstructionGraphNode lastInst = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            if (inst.getInstruction().getAddress().toLong() % 0x100 == 0) {
                lastInst = inst;
            }
        }

        return lastInst;

    }

    private boolean isRetrunValueTainted() {

        searchTaintedRetrunValue();
        if (taintedReilPaths.isEmpty()) {
            return false;
        }

        return true;
    }

    private boolean checkTaintedValue(DefUseChain.DefUseNode node) {

        ReilInstruction inst = node.getInst().getInstruction();
        InstructionGraphNode lastInstruction = getLastInstruction(func);

        if (inst.equals(lastInstruction)) {
            dnagerousness = Dangerousness.PE;
            return true;
        }
        return false;

    }

    private void searchTaintedRetrunValue() {
        // All the graphs is analyzed at this function

        for (DefUseChain.DefUseGraph duGraph : duGraphs) {
            Stack<DefUseChain.DefUseNode> stackDFS = new Stack<DefUseChain.DefUseNode>();
            Set<DefUseChain.DefUseNode> visitedNodes = new HashSet<DefUseChain.DefUseNode>();
            searchTaintRetrunValueDFS(stackDFS, visitedNodes, duGraph.getNodes().get(0));
        }
    }

    private void searchTaintRetrunValueDFS(Stack<DefUseChain.DefUseNode> stackDFS,
            Set<DefUseChain.DefUseNode> visitedNode, DefUseChain.DefUseNode duNode) {

        // current node processing
        visitedNode.add(duNode);
        stackDFS.push(duNode);
        if (checkTaintedValue(duNode)) {
            List<DefUseChain.DefUseNode> exploitPath = new ArrayList<DefUseChain.DefUseNode>();
            exploitPath.addAll(stackDFS);
            taintedReilPaths.put(duNode, exploitPath);

            // printTaintedReilPaths();
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

    public int getTotal_e_count() {
        return 0;
    }

    public int getTotal_pe_count() {
        return 0;
    }

}
