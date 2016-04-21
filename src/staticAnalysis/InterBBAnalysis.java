package staticAnalysis;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariable;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariablesManager;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;

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
        findUsedLocalVariables();
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
        for(String operand : usedOperands)
        {
            if(operand.contains("var_"))
            {
                String variable = stringOfLocalVariable(operand);
                System.out.println(variable);
            }
        }
    }
    private String stringOfLocalVariable(String operand)
    {
        String localVariable = operand.substring(4,operand.length()-1);
        
        
        for(int i=0; i<localVariable.length()-5; i++)
        {
            if(localVariable.startsWith("var_") )
            {
                localVariable = localVariable.substring(1, localVariable.length());                
            }
        }
        
        if(localVariable.length()==0)
        {
            LogConsole.log("error : InterBBAnalysis - stringOfLocalVariable() - localVariable's length is 0" );
        }
        return localVariable;
              
    }
    
    
    private void findUsedarguments()
    {
        
    }
    
    
    

}
