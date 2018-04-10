package plugin.java.com.plas.crashfilter.analysis.helper.Graph;

import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by User on 2017-12-11.
 */
public class DefUseGraph extends SimpleGraph {
    private List<DefUseNode> nodes = new ArrayList<DefUseNode>();
    private List<DefUseEdge> edges = new ArrayList<DefUseEdge>();

    private DefUseGraph() {
        super();
    }

    public static DefUseGraph createDefUseGraph( Map<InstructionGraphNode, List<InstructionGraphNode>> chains, InstructionGraphNode inst){
        Map<InstructionGraphNode, DefUseNode> visitedNodes = new HashMap<>();
        DefUseGraph duGraph = new DefUseGraph();

        DefUseNode duNode = new DefUseNode(inst);
        return createDefUseGraph(duGraph, visitedNodes, duNode, chains);
    }

    private static DefUseGraph createDefUseGraph(DefUseGraph duGraph, Map<InstructionGraphNode, DefUseNode> visitedNodes,
                                        DefUseNode duNode, Map<InstructionGraphNode, List<InstructionGraphNode>> chains){
        duGraph.addNode(duNode);
        visitedNodes.put(duNode.getInst(), duNode);

        List<InstructionGraphNode> duNodes = new ArrayList<InstructionGraphNode>();

        boolean hasDUInst = false;
        for (InstructionGraphNode inst : chains.keySet()) {
            if (inst.getInstruction().getAddress().toLong() == duNode.getInst().getInstruction().getAddress().toLong()) {
                duNodes = chains.get(inst);
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
                    createDefUseGraph(duGraph, visitedNodes, newNode, chains);
                }
            }
        }
        return duGraph;
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
