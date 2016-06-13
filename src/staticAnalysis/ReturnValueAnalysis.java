package staticAnalysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import com.google.security.zynamics.binnavi.API.reil.ReilFunction;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import data.ReilInstructionResolve;
import staticAnalysis.DefUseChain.DefUseNode;
import staticAnalysis.RDAnalysis.RDLatticeElement;

public class ReturnValueAnalysis implements TaintSink {
    private List<DefUseChain.DefUseGraph> duGraphs;
    private Function func;
    private Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> taintedReilPaths = new HashMap<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>>();
    private Map<Instruction, List<Instruction>> taintedArmPaths = new HashMap<Instruction, List<Instruction>>();


    private IStateVector<InstructionGraphNode, RDLatticeElement> RDResult;
    private ILatticeGraph<InstructionGraphNode> graph;

    public ReturnValueAnalysis(List<DefUseChain.DefUseGraph> duGraphs, Function func, Map<String, String> crashFilteringResult, IStateVector<InstructionGraphNode, RDLatticeElement> RDResult, ILatticeGraph<InstructionGraphNode> graph) {
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
            
            taintedArmPaths.put(exploitPoint, armPath);
            
      /*      if (taintedArmPaths.isEmpty()) {
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
            }*/
        }
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
        
        RDLatticeElement rdLatticeElement = RDResult.getState(lastInstruction);
        if(rdLatticeElement == null)
        {
            System.out.println("RDLatticeElement is null");
            System.exit(-1);
        }
        
        return isReachableToLastInstruction(inst, rdLatticeElement);
    }

    private boolean isReachableToLastInstruction(InstructionGraphNode inst, RDLatticeElement rdLatticeElement) {
        return rdLatticeElement.getReachableInstList().contains(inst);
    }

    private InstructionGraphNode getLastInstruction(Function func) {

      
        InstructionGraphNode lastInst = null;
        for (InstructionGraphNode inst : graph.getNodes()) {
            if( inst.getInstruction().getAddress().toLong() % 0x100 == 0)
            {
                lastInst = inst;
            }
        }

        return lastInst;

    }


    private boolean isRetrunValueTainted() {

        searchTaintedRetrunValue();
        projectReilExploitToArmExploit();
        if (taintedReilPaths.isEmpty()) {
            return false;
        }

        return true;
    }

    private boolean isTaintedReturnValue(DefUseChain.DefUseNode node) {

        ReilInstruction inst = node.getInst().getInstruction();
        
        //if (isDefInstruction(inst)) {        
        
            if (isReachableAtReturn(node.getInst())) {
               
                return true;
            }
        //}
        return false;

    }

    private boolean isDefInstruction(ReilInstruction inst) {
        if(inst.getMnemonic().equals("str"))
            return true;
        if( isBinaryOperation(inst) )
            return true;
        
        return false;
    }

    private boolean isDefRetrunVauleWithTaint(ReilInstruction def) {
        return (def.getThirdOperand().getValue().equals("eax")
                || def.getThirdOperand().getValue().equals("r0"));
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

       
            System.out.println("search : " + duGraph.getNodes().get(0));
            searchTaintRetrunValueDFS(stackDFS, visitedNodes, duGraph.getNodes().get(0));
        }


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
            
            
            //printTaintedReilPaths();
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
    private void printTaintedReilPaths()
    {
         Set<DefUseNode> keySet = taintedReilPaths.keySet();
        
        for(DefUseNode key : keySet)
        {
            System.out.println("src : "+ key);
            
            if(taintedReilPaths.get(key) == null) continue;
            
            for(DefUseNode inst : taintedReilPaths.get(key))
            {
                System.out.println("\t"+ inst);
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
