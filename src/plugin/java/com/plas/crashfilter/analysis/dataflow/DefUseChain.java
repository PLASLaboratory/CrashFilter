package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.*;
import com.google.security.zynamics.binnavi.standardplugins.utils.Pair;
import plugin.java.com.plas.crashfilter.analysis.MemoryChecker;
import plugin.java.com.plas.crashfilter.analysis.helper.CrashSourceAdder;
import plugin.java.com.plas.crashfilter.analysis.memory.MLocLatticeElement;
import plugin.java.com.plas.crashfilter.analysis.memory.RTable.RTable;
import plugin.java.com.plas.crashfilter.analysis.memory.env.Env;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;
import sun.rmi.runtime.Log;

import java.util.*;
import java.util.Map.Entry;

public class DefUseChain {
    //dstUseChain : dest가 def로 정의되고, 나중에 유즈되는 곳(src)의 주소를 정의함
    private Map<InstructionGraphNode, List<InstructionGraphNode>> defUseChains = new HashMap<InstructionGraphNode, List<InstructionGraphNode>>();
    private Map<InstructionGraphNode, List<InstructionGraphNode>> useDefChains = new HashMap<InstructionGraphNode, List<InstructionGraphNode>>();
    private IStateVector<InstructionGraphNode, DefLatticeElement> RDResult;
    private ILatticeGraph<InstructionGraphNode> graph;
    private List<DefUseGraph> duGraphs = new ArrayList<DefUseGraph>();
    private IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult;
    private boolean doCrashSrcAnalysis = false; // if it is true , ver 1.2
    private long crashPointAddress = 0;
    private InstructionGraph defUseGraph;
    private List<InstructionGraphNode> resultSet;

    //pair first is def, pair second is use and string is operand propagated
    private Map<InstructionGraphNode, Set<Pair<InstructionGraphNode, String>>> propagateOp = new LinkedHashMap<>();
    //For Data dependence graph
    //key of ddgSrcNode is InstructionGraphNode of dst.
    //
    Set<String> ddgEdges = new HashSet<>();

    public void setMemoryResult(IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult) {
        this.mLocResult = mLocResult;
    }


    public DefUseChain(IStateVector<InstructionGraphNode, DefLatticeElement> rDResult,
            ILatticeGraph<InstructionGraphNode> graph, Long crashPointAddress, boolean doCrashSrcAnalysis) {
        this.RDResult = rDResult;
        this.graph = graph;
        this.crashPointAddress = crashPointAddress;
        this.doCrashSrcAnalysis = doCrashSrcAnalysis;
    }

    private boolean isDefUsed(InstructionGraphNode def, InstructionGraphNode use, boolean rdContain) throws MLocException {
        List<ReilOperand> destList = ReilInstructionResolve.resolveReilInstructionDest(def);
        List<ReilOperand> srcList = ReilInstructionResolve.resolveReilInstructionSrc(use);

        // if source set is empty, we don't need to check anymore
        if (srcList.isEmpty()) {
            return false;
        }

        switch (ReilInstructionResolve.getKindInst(use)) {
            case STM:
                switch (ReilInstructionResolve.getKindInst(def)) {
                    case STM:
                        return false;
                    case OTHERS:
                    case LDM:
                        for (ReilOperand dest : destList) {
                            if (ReilHelpers.isRegister(dest)) {
                                if (dest.getValue().equals(use.getInstruction().getFirstOperand().getValue())) {
                                    String ss = "Def: " + def.toString() + "Use: " + use.toString() + "\n";
                                    return true;
                                } else
                                    return false;
                            }
                        }
                    default:
                        break;
                }
            case LDM:
                switch (ReilInstructionResolve.getKindInst(def)) {
                    case STM:
                        // In case of global memory access
                        // We can be aware of the position of direct memory access, so
                        // we are able to consider this case

                        if (ReilInstructionResolve.isLiteralDirectAccess(use)) {
                            if (ReilInstructionResolve.isLiteralDirectAccess(def)) {
                                if (use.getInstruction().getFirstOperand().getValue()
                                        .equals(def.getInstruction().getThirdOperand().getValue())) {
                                    return true;
                                } else
                                    return false;
                            } else if (ReilInstructionResolve.isRegisterIndirectAccess(def))
                                return true;
                        } else if (ReilInstructionResolve.isRegisterIndirectAccess(use)
                                && ReilInstructionResolve.isLiteralDirectAccess(def)) {
                            return true;
                        }

                        return true;
                    case LDM:
                    case OTHERS:
                        for (ReilOperand dest : destList) {
                            for (ReilOperand src : srcList) {
                                if (dest.getValue().equals(src.getValue()))
                                    return true;
                            }
                        }
                        return false;
                    default:
                        break;
                }
            default:
                switch (ReilInstructionResolve.getKindInst(def)) {
                    case STM:
                        return false;
                    case OTHERS:
                        for (ReilOperand dest : destList) {
                            for (ReilOperand src : srcList) {
                                if (ReilHelpers.isRegister(dest) && ReilHelpers.isRegister(src)) {
                                    if (dest.getValue().equals(src.getValue())) {
                                        if(rdContain) {
                                            propagateOp.get(use).add(new Pair<>(def, dest.toString()));
                                        }
                                        return true;
                                    }
                                }
                            }
                        }
                    case LDM:
                        for (ReilOperand dest : destList) {
                            for (ReilOperand src : srcList) {
                                if (ReilHelpers.isRegister(dest) && ReilHelpers.isRegister(src)) {
                                    if (dest.getValue().equals(src.getValue())) {
                                        return true;
                                    }
                                }
                            }
                        }
                    default:
                        break;
                }
        }
        return false;
    }

    // we have to add some memory related task after VSA
    public void defUseChaining() throws MLocException {
        List<InstructionGraphNode> uses = null;

        int count = 0;
        int count2 = 0;

        List<InstructionGraphNode> insts = graph.getNodes();

        
        if (doCrashSrcAnalysis) {
            //TODO
            insts = CrashSourceAdder.getInstructionlist(graph, crashPointAddress);
        }

        for (InstructionGraphNode def : insts) {
            uses = new ArrayList<InstructionGraphNode>();
            for (InstructionGraphNode use : graph.getNodes()) {
                if(!this.propagateOp.containsKey(use)) {
                    Set<Pair<InstructionGraphNode, String>> pairs = new HashSet<>();
                    this.propagateOp.put(use, pairs);
                }
                Set<InstructionGraphNode> reachableInstList = RDResult.getState(use).getInstList();
                boolean rdContain = reachableInstList.contains(def);

                for (InstructionGraphNode node : reachableInstList) {
                    if (def.getInstruction().getAddress().toLong() == node.getInstruction().getAddress().toLong()) {
                        rdContain = true;
                    }
                }

                Address defAddress = ReilHelpers.toNativeAddress(def.getInstruction().getAddress());
                boolean isDU = isDefUsed(def, use, rdContain);

                boolean flag = (def != use) && rdContain && isDU;


                if (flag) {
                    MemoryChecker mc = new MemoryChecker();
                    mc.setMLocResult(mLocResult);
                    uses.add(use);

                    if (mLocResult != null) {
                        if (mc.differentMemoryCheckEnv(def, use)) {
                            count++;
                            uses.remove(use);
                            // LogConsole.log(flag+" Defferent\n");
                            break;
                        } else {
                            String edgeString = ReilHelpers.toReilAddress(use.getInstruction().getAddress()).toHexString()+":"+"MEM_READ or MEM_WRITE"+":"
                                    +ReilHelpers.toReilAddress(def.getInstruction().getAddress()).toHexString();
                            ddgEdges.add(edgeString);
                            propagateOp.get(use).add(new Pair<>(def, "mem"));
                            count2++;
                        }
                    }
                }
                if(propagateOp.get(use).size()==0)
                    propagateOp.remove(use);
            }

            // Here, if there is no any use that uses the relevant def, we just
            // ignore the def
            if (!uses.isEmpty()) {
                defUseChains.put(def, uses);
            }
        }
        LogConsole.log("disconnected  : " + count + "/" + count2 + "\n");

    }

    public Map<InstructionGraphNode,  Set<Pair<InstructionGraphNode, String>>> getPropagateOp(){
        return propagateOp;
    }

    public void printChain() {

        for (Entry<InstructionGraphNode, List<InstructionGraphNode>> defUseChain : defUseChains.entrySet()) {
            LogConsole.log("<def> : " + defUseChain.getKey().getInstruction().toString() + "\n");
            for (InstructionGraphNode use : defUseChain.getValue()) {
                LogConsole.log("\t [use] : " + use.getInstruction().toString() + "\n");
            }
            LogConsole.log("\n");
        }

    }

    public Map<InstructionGraphNode, List<InstructionGraphNode>> getDefUseChains() {
        return defUseChains;
    }

    public void printDuGraph(DefUseGraph duGraph) {
        if (duGraph.getNodes().isEmpty()) {
            LogConsole.log("graph empty!!\n");
        }

        for (DefUseNode node : duGraph.getNodes()) {
            LogConsole.log("[Node] " + node.getInst().getInstruction().toString() + " : \n");
            for (DefUseNode outgoingNode : node.getChildren()) {
                LogConsole.log("\t" + outgoingNode.getInst().toString() + "\n");
            }
            LogConsole.log("\n");
        }
    }

    public List<DefUseGraph> getDuGraphs() {
        return duGraphs;
    }


    public void createDefUseGraph(InstructionGraphNode inst) {
        Map<InstructionGraphNode, DefUseNode> visitedNodes = new HashMap<InstructionGraphNode, DefUseNode>();
        DefUseGraph duGraph = new DefUseGraph();

        DefUseNode duNode = new DefUseNode(inst);
        createDefUseGraph(duGraph, visitedNodes, duNode);

        duGraphs.add(duGraph);
    }

    // using recursion for creating DEF-USE Graph
    private void createDefUseGraph(DefUseGraph duGraph, Map<InstructionGraphNode, DefUseNode> visitedNodes,
            DefUseNode duNode) {

        duGraph.addNode(duNode);
        visitedNodes.put(duNode.getInst(), duNode);

        List<InstructionGraphNode> duNodes = new ArrayList<InstructionGraphNode>();

        boolean hasDUInst = false;
        for (InstructionGraphNode inst : defUseChains.keySet()) {
            if (inst.getInstruction().getAddress().toLong() == duNode.getInst().getInstruction().getAddress().toLong()) {
                duNodes = defUseChains.get(inst);
                hasDUInst = true;
                break;
            }
        }
 
        if (hasDUInst) {

            for (InstructionGraphNode use : duNodes) {
                if (visitedNodes.containsKey(use)) {
                    DefUseEdge duEdge = new DefUseEdge(duNode, visitedNodes.get(use));
                    duNode.link(duNode, visitedNodes.get(use), duEdge);
                    duGraph.addEdge(duEdge);
                } else {
                    DefUseNode newNode = new DefUseNode(use);
                    DefUseEdge duEdge = new DefUseEdge(duNode, newNode);
                    duNode.link(duNode, newNode, duEdge);
                    duGraph.addEdge(duEdge);
                    createDefUseGraph(duGraph, visitedNodes, newNode);
                }
            }
        }

    }

    public List<InstructionGraphNode> getUseSet(List<InstructionGraphNode> insts){
        getDeepUseSet(new HashSet<>(insts));
        return this.resultSet;
    }
    private void getDeepUseSet(Set<InstructionGraphNode> defs){
        for(InstructionGraphNode defInstruction: defs){
            this.getUseSet(defInstruction);
        }
    }

    private void getUseSet(InstructionGraphNode def){
        this.resultSet.add(def);
        if(this.defUseChains.containsKey(def)) {
            for (InstructionGraphNode use : this.defUseChains.get(def)) {
                getUseSet(use);
            }
        }
    }
    public class DefUseNode {
        private InstructionGraphNode inst;
        private List<DefUseNode> children = new ArrayList<DefUseNode>();
        private List<DefUseNode> parents = new ArrayList<DefUseNode>();

        private List<DefUseEdge> incomingEdges = new ArrayList<DefUseEdge>();
        private List<DefUseEdge> outcomingEdges = new ArrayList<DefUseEdge>();

        DefUseNode(final InstructionGraphNode inst) {
            this.inst = inst;
        }

        public String toString() {
            return this.inst + "";
        }

        public InstructionGraphNode getInst() {
            return inst;
        }

        public List<DefUseNode> getChildren() {
            return children;
        }

        public List<DefUseNode> getParents() {
            return parents;
        }

        public List<DefUseEdge> getIncomingEdges() {
            return incomingEdges;
        }

        public List<DefUseEdge> getOutcomingEdges() {
            return outcomingEdges;
        }

        public void addChild(DefUseNode child) {
            children.add(child);
        }

        public void addParent(DefUseNode parent) {
            parents.add(parent);
        }

        public void addIncomingEdge(DefUseEdge incomingEdge) {
            incomingEdges.add(incomingEdge);
        }

        public void addOutComingEdge(DefUseEdge outcomingEdge) {
            outcomingEdges.add(outcomingEdge);
        }

        public void removeChild(DefUseNode child) {
            children.remove(child);
        }

        public void removeParent(DefUseNode parent) {
            parents.remove(parent);
        }

        public void removeIncomingEdge(DefUseEdge incomingEdge) {
            incomingEdges.remove(incomingEdge);
        }

        public void removeOutComingEdge(DefUseEdge outcomingEdge) {
            outcomingEdges.remove(outcomingEdge);
        }

        void link(final DefUseNode source, final DefUseNode target, final DefUseEdge edge) {
            if ((source != null) && (target != null) && (edge != null)) {
                target.addParent(source);
                source.addChild(target);
                target.addIncomingEdge(edge);
                source.addOutComingEdge(edge);
            } else
                return;
        }

        void unlink(final DefUseNode source, final DefUseNode target, final DefUseEdge edge) {
            if ((source != null) && (target != null) && (edge != null)) {
                target.removeParent(source);
                source.removeChild(target);
                target.removeIncomingEdge(edge);
                source.removeOutComingEdge(edge);
            } else
                return;
        }

    }

    @SuppressWarnings("unused")
    public class DefUseEdge {
        private DefUseNode source;
        private DefUseNode target;

        public DefUseEdge(DefUseNode source, DefUseNode target) {
            this.source = source;
            this.target = target;
        }

        public DefUseNode getSource() {
            return source;
        }

        public DefUseNode getTarget() {
            return target;
        }

        public String toString() {
            return source + "->" + target + "\n";
        }

    }


    public class DefUseGraph {
        private List<DefUseNode> nodes = new ArrayList<DefUseNode>();
        private List<DefUseEdge> edges = new ArrayList<DefUseEdge>();

        DefUseGraph() {

        }

        public List<DefUseNode> getNodes() {
            return nodes;
        }

        public List<DefUseEdge> getEdges() {
            return edges;
        }

        public void addNode(DefUseNode node) {
            nodes.add(node);
        }

        public void addEdge(DefUseEdge edge) {
            edges.add(edge);
        }

    }

}
