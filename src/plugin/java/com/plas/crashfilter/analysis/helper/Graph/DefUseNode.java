package plugin.java.com.plas.crashfilter.analysis.helper.Graph;

import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefUseChain;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by User on 2017-12-11.
 */
public class DefUseNode {
    private InstructionGraphNode inst;
    private List<DefUseNode> children = new ArrayList<DefUseNode>();
    private List<DefUseNode> parents = new ArrayList<DefUseNode>();

    private List<DefUseEdge> incomingEdges = new ArrayList<DefUseEdge>();
    private List<DefUseEdge> outcomingEdges = new ArrayList<DefUseEdge>();

    public DefUseNode(final InstructionGraphNode inst) {
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
}
