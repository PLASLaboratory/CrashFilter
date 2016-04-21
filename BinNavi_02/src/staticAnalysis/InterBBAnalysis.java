package staticAnalysis;

import java.util.ArrayList;
import java.util.List;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariable;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariablesManager;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;

public class InterBBAnalysis {

    Module module;
    Function function;

    List<GlobalVariable> globalVariables = new ArrayList<GlobalVariable>();
    
    
    List<String> usedGlobalVariables = new ArrayList<String>();
    List<String> usedLocalVariables = new ArrayList<String>();
    List<String> usedArguments = new ArrayList<String>();
    
    List<String> usedOperands = new ArrayList<String>();

    public InterBBAnalysis(Module module, Function function) {
        this.module = module;
        this.function = function;
        
        initGlobalVariables();
        usedOperands = findUsedOperands();
    }
    
    private void initGlobalVariables()
    {
        GlobalVariablesManager gvm = module.getGlobalVariablesManager();
        gvm.getVariables();
            
        globalVariables = gvm.getVariables();       
    }
    
    private List<String> findUsedOperands()
    {
        List<String> usedOperands = new ArrayList<String>();
        
        FlowGraph flowGraph = function.getGraph();
        List<BasicBlock> basicBlocks = flowGraph.getNodes();
        for(BasicBlock bb : basicBlocks)
        {
            List<Instruction> instructions = bb.getInstructions();
            for(Instruction instruction : instructions)
            {
                List<Operand> operands = instruction.getOperands();
                for(Operand operand :  operands)
                {
                    usedOperands.add(operand.toString());
                    System.out.println(operand.toString());
                }
            }
        }
        
        return usedOperands;
    }
    
    private void findUsedGlobalVariables()
    {
        
    }
    
    private void findUsedLocalVariables()
    {
        
    }
    
    
    private void findUsedarguments()
    {
        
    }
    
    
    

}
