package plugin.java.com.plas.crashfilter.analysis.helper;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.ModuleHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefUseChain;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Created by User on 2017-11-22.
 */
public class ArgumentAnalysis implements TaintSink {
    /*
    This class analyze whether Caller taint callee
    콜러가 callee 에 영향울 주었는지 분석함
    즉, callee 의 오염된 명령어가 argument 로 부터 영향을 받고
    caller 에서 callee 의 argument 에 영향을 주었는지 분석
     */
    private Function func;
    private List<DefUseChain.DefUseGraph> udGraphs;
    private VariableFinder vf;

    public ArgumentAnalysis(Function func, List<DefUseChain.DefUseGraph> udGraphs, VariableFinder vf) {
        this.func = func;
        this.udGraphs = udGraphs;
        this.vf = vf;
    }

    public static boolean isReachableToArgInstruction(Function func, DefUseChain.DefUseGraph udGraph, VariableFinder vf){
        //List 말고 Graph만 입력받기
        Set<Instruction> argInstructions = vf.getUsedArgumentInstructions();
        Set<InstructionGraphNode> reachableInsts = new HashSet<>();
        for(DefUseChain.DefUseNode node: udGraph.getNodes()){
            for(Instruction inst : argInstructions) {
                if (inst.getAddress().equals(ReilHelpers.toNativeAddress(node.getInst().getInstruction().getAddress())))
                    return true;
            }
        }
        return false;
    }


    @Override
    public boolean isTaintSink() {
        return false;
    }

    @Override
    public Map<Instruction, List<Instruction>> getExploitArmPaths() {
        return null;
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
