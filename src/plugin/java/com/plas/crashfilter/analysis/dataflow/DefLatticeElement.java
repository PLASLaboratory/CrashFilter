package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeElement;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by User on 2017-06-15.
 */
public class DefLatticeElement implements ILatticeElement<DefLatticeElement> {

    public InstructionGraphNode inst;
    public Set<InstructionGraphNode> instList = new HashSet<InstructionGraphNode>();
    private Set<InstructionGraphNode> killList = new HashSet<InstructionGraphNode>();

    public void setInst(InstructionGraphNode inst) {
        this.inst = inst;
    }

    public InstructionGraphNode getInst() {
        return inst;
    }

    public Set<InstructionGraphNode> getInstList() {
        return instList;
    }

    public Set<InstructionGraphNode> getKillList() {
        return killList;
    }

    public void intersectInstList(Set<InstructionGraphNode> state) { this.instList.retainAll(state); }
    
    public void unionInstList(Set<InstructionGraphNode> state) {
        this.instList.addAll(state);
    }

    public void unionKillList(Set<InstructionGraphNode> killList) {
        this.killList.addAll(killList);
    }

    public void removeAllInstList(Set<InstructionGraphNode> instList) {
        this.instList.removeAll(instList);
    }

    public void insertInst(InstructionGraphNode inst) {
        this.instList.add(inst);
    }
    public void insertInstAll(List<InstructionGraphNode> nodes) { this.instList.addAll(nodes); }
    public void insertKill(InstructionGraphNode inst) {
        this.killList.add(inst);
    }

    public DefLatticeElement transLatticeElement(List<DefLatticeElement> elements) {
        //List -->DefLatticeElement
        DefLatticeElement combinedElement = new DefLatticeElement();
        for (DefLatticeElement element : elements) {
            combinedElement.unionInstList(element.getInstList());
        }
        return combinedElement;
    }
    public DefLatticeElement combineIntersect(List<DefLatticeElement> elements) {
        DefLatticeElement combinedElement = new DefLatticeElement();
        for (DefLatticeElement element : elements) {
            combinedElement.intersectInstList(element.getInstList());
        }
        return combinedElement;
    }

    public boolean equals(DefLatticeElement rhs) {
        if (rhs.getInstList().containsAll(instList)) {
            if (instList.size() == rhs.getInstList().size()) {
                if(killList.size() == rhs.killList.size())
                    return true;
            }
        }
        return false;
    }

    public boolean greaterThan(DefLatticeElement rhs) {
        //목성균이 새로 정의함
        if (rhs.getInstList().containsAll(instList)) {
            if (instList.size() > rhs.getInstList().size()) {
                return true;
            }

        }
        return false; // error - it is not monotone
    }
    public boolean lessThan(DefLatticeElement rhs) {
        if (rhs.getInstList().containsAll(instList)) {
            if (instList.size() < rhs.getInstList().size()) {
                return true;
            }

        }
        return false; // error - it is not monotone
    }

}
