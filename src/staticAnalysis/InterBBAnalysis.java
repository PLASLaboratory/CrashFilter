package staticAnalysis;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.Callgraph;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.FunctionEdge;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;

import data.CrashPoint;
import helper.VariableFinder;

public class InterBBAnalysis {

    Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();
    Function currentFunction;
    private VariableFinder variableFinder;
    private Module module;

    public InterBBAnalysis(Module module, Function function) {
        currentFunction = function;
        variableFinder = new VariableFinder(module, currentFunction);
        this.module = module;

        callees(currentFunction);
    }

    public List<Function> callees(Function function) {

        Callgraph callgraph =  module.getCallgraph();
                
        for(FunctionEdge fe : callgraph.getEdges())
        {
            if (fe.getSource().getFunction().getAddress().toLong() == function.getAddress().toLong())
            {
                System.out.println("target : " + fe.getTarget());
                System.out.println("target function : " + fe.getTarget().getFunction());
                System.out.println("target : function addr : " + fe.getTarget().getFunction().getAddress());
            }
        }
        
        FlowGraph graph = function.getGraph();

        for (BasicBlock bb : graph.getNodes()) {
            for (Instruction instruction : bb.getInstructions()) {
              /*  
                System.out.println("=========");
                System.out.println("inst : "+instruction);
                System.out.println("inst mnemonic : "+instruction.getMnemonic());
                System.out.println("inst data: "+instruction.getData());
                System.out.println("inst : comment"+instruction.getComment());
                System.out.println("inst architecture: "+instruction.getArchitecture());
                
               */ 
                try {
                    System.out.println("inst : reilcode"+instruction.getReilCode());
                } catch (InternalTranslationException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                
                
                if (instruction.getMnemonic().equals("call")) {
                   
                    

                } else if (instruction.getMnemonic().equals("BL")) {
                    for (Operand oprand : instruction.getOperands()) {
                        System.out.println(instruction);
                    }
                }
            }
        }
        return null;

    }

    public boolean dontHaveToAnalysis() {
        return dontHaveArgument() && dontUseGlobalVariable();
    }

    public boolean dontHaveArgument() {
        return variableFinder.getUsedArguments().size() == 0;
    }

    public boolean dontUseGlobalVariable() {
        return variableFinder.getUsedGlobalVariables().size() == 0;
    }

}
