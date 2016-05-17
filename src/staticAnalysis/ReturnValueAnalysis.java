package staticAnalysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import data.ReilInstructionResolve;
import staticAnalysis.RDAnalysis.RDLatticeElement;

public class ReturnValueAnalysis implements TaintSink {
    private List<DefUseChain.DefUseGraph> duGraphs;
    private Function func;
    private Map<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>> taintedReilPaths = new HashMap<DefUseChain.DefUseNode, List<DefUseChain.DefUseNode>>();
    private Map<Instruction, List<Instruction>> taintedArmPaths = new HashMap<Instruction, List<Instruction>>();

    private Map<String, String> crashFilteringResult;
    private String crashAddr;

    private int e_count = 0;
    private int pe_count = 0;

    private int total_e_count = 0;

    private int total_pe_count = 0;
    private IStateVector<InstructionGraphNode, RDLatticeElement> RDResult;

    public int getTotal_e_count() {
        return total_e_count;
    }

    public int getTotal_pe_count() {
        return total_pe_count;
    }

    public ReturnValueAnalysis(List<DefUseChain.DefUseGraph> duGraphs, Function func, Long crashAddr,
            Map<String, String> crashFilteringResult, IStateVector<InstructionGraphNode, RDLatticeElement> RDResult) {
        this.duGraphs = duGraphs;
        this.func = func;
        this.RDResult = RDResult;
        this.crashAddr = Long.toHexString(crashAddr);
        this.crashFilteringResult = crashFilteringResult;
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

    private boolean isLastDefOfReturnValue() {
        // TODO Auto-generated method stub
        if (RDResult == null) {
            System.out.println("error : RVA- isLastDefOfReturnValue()");
        }

        return false;
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
        if (ReilHelpers.isRegister(use.getInstruction().getThirdOperand())) {
            for (ReilOperand op : ReilInstructionResolve.resolveReilInstructionDest(def)) {
                if (use.getInstruction().getThirdOperand().getValue().equals(op.getValue())) {
                    return true;
                }
            }
            return false;
        } else
            return false;

    }

    private boolean isDefUsedInAddressToStore(InstructionGraphNode use, InstructionGraphNode def) {
        if (ReilHelpers.isRegister(use.getInstruction().getThirdOperand())) {
            for (ReilOperand op : ReilInstructionResolve.resolveReilInstructionDest(def)) {
                if (use.getInstruction().getThirdOperand().getValue().equals(op.getValue())) {
                    return true;
                }
            }
            return false;
        } else
            return false;
    }

    private boolean isDefUsedInDataToStore(InstructionGraphNode use, InstructionGraphNode def) {
        if (ReilHelpers.isRegister(use.getInstruction().getFirstOperand())) {
            for (ReilOperand op : ReilInstructionResolve.resolveReilInstructionDest(def)) {
                if (use.getInstruction().getFirstOperand().getValue().equals(op.getValue())) {
                    return true;
                }
            }
            return false;
        } else
            return false;
    }

    // to check the parents
    // ---------------------------------------------------------------------
    private boolean isTaintedReturnValue(DefUseChain.DefUseNode node) {

        ReilInstruction inst = node.getInst().getInstruction();

        if (inst.getMnemonic().equals("add") || inst.getMnemonic().equals("sub") || inst.getMnemonic().equals("mul")|| inst.getMnemonic().equals("div")) {
            return false;
        }
        
        /*
        if (inst.getMnemonic().equals("jcc")) {
            for (DefUseChain.DefUseNode duNode : node.getParents()) {
                if (isDefUsedInAddressToBranch(node.getInst(), duNode.getInst())) {
                    // LogConsole.log("E - jcc\n");
                    e_count++;
                    return true;
                }
            }
            return false;
        }

        else if (inst.getMnemonic().equals("stm")) {
            for (DefUseChain.DefUseNode duNode : node.getParents()) {
                if (isDefUsedInAddressToStore(node.getInst(), duNode.getInst())) {
                    if (isDefUsedInDataToStore(node.getInst(), duNode.getInst())) {
                        // LogConsole.log("E - stm addr & data \n");
                        e_count++;
                        return true; // Exploitable
                    }
                    // LogConsole.log("PE - stm address\n");
                    pe_count++;
                    return true; // Probably Exploitable
                } else if (isDefUsedInDataToStore(node.getInst(), duNode.getInst())) {
                    // LogConsole.log("PE - stm data\n");
                    pe_count++;
                    return true;
                }
            }
            return false;
        }*/

        else {
            return false;
        }

    }

    private void searchTaintedRetrunValue() {
        // All the graphs is analyzed at this function
        e_count = 0;
        pe_count = 0;

        for (DefUseChain.DefUseGraph duGraph : duGraphs) {
            Stack<DefUseChain.DefUseNode> stackDFS = new Stack<DefUseChain.DefUseNode>();
            Set<DefUseChain.DefUseNode> visitedNodes = new HashSet<DefUseChain.DefUseNode>();

            // We find all possible exploitable instruction in this function
            // We consider the possibility in detail after this process
            // Depth First Search Algorithm

            System.out.println("search : " + duGraph.getNodes().get(0));
            searchExploitableDFS(stackDFS, visitedNodes, duGraph.getNodes().get(0));
        }

        printResultOnLog();

        total_e_count += e_count;
        total_pe_count += pe_count;

        putFilteringResult(crashAddr, e_count, pe_count, crashFilteringResult);
    }

    private void printResultOnLog() {

        LogConsole.log("crashAddr  : " + crashAddr + "\n");
        LogConsole.log("e  : " + e_count + "\n");
        LogConsole.log("pe : " + pe_count + "\n");
        LogConsole.log("total : " + (e_count + pe_count) + "\n");
    }

    private void putFilteringResult(String crashAddr, int e_count, int pe_count,
            Map<String, String> crashFilteringResult) {
        if (e_count > 0) {
            crashFilteringResult.put(crashAddr, "E");
        } else if (pe_count > 0) {
            crashFilteringResult.put(crashAddr, "PE");
        } else {
            crashFilteringResult.put(crashAddr, "NE");
        }
    }

    private void searchExploitableDFS(Stack<DefUseChain.DefUseNode> stackDFS, Set<DefUseChain.DefUseNode> visitedNode,
            DefUseChain.DefUseNode duNode) {

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
                searchExploitableDFS(stackDFS, visitedNode, node);
            }
        }
    }

    private boolean isLastInstruction() {
        return false;
    }

}
