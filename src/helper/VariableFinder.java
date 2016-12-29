package helper;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariable;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariablesManager;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;

public class VariableFinder {

    private Module module;
    private Function function;

    private List<GlobalVariable> globalVariables = new ArrayList<GlobalVariable>();

    private Set<String> usedGlobalVariables = new HashSet<String>();
    private Set<String> usedLocalVariables = new HashSet<String>();
    private Set<String> usedArguments = new HashSet<String>();
    
    private Set<String> usedOperands = new HashSet<String>();

    
    private Set<Instruction> usedArgumentInstructions = new HashSet<Instruction>();
    private Set<Instruction> usedGlobalVariableInstructions = new HashSet<Instruction>();
    
    public Set<String> getUsedGlobalVariables() {
        return usedGlobalVariables;
    }

    public Set<String> getUsedLocalVariables() {
        return usedLocalVariables;
    }

    public Set<String> getUsedArguments() {
        return usedArguments;
    }

    public VariableFinder(Module module, Function function) {
        this.module = module;
        this.function = function;

        initGlobalVariables();

        usedOperands = findUsedOperands();

        findUsedLocalVariables();
        findUsedArguments();
        findUsedGlobalVariables();        
        usedArgumentInstructions = findArgumentInstructions();
        usedGlobalVariableInstructions = findGlobalVariableInstructions();
    }

    private HashSet<Instruction> findGlobalVariableInstructions() {

        HashSet<Instruction> usedGlobalVariableInstructions = new HashSet<Instruction>();
        FlowGraph flowGraph;
        try {
            flowGraph = function.getGraph();
            String funcAddr = function.getAddress().toHexString();
            System.out.println("0x"+funcAddr);
        }catch(Exception e)
        {
            System.out.println("findGlobalVariableInstructions!");
            return usedGlobalVariableInstructions;
        }
        finally {
        }
        List<BasicBlock> basicBlocks = flowGraph.getNodes();
        
        for (BasicBlock bb : basicBlocks) {
            List<Instruction> instructions = bb.getInstructions();
            for (Instruction instruction : instructions) {
                List<Operand> operands = instruction.getOperands();
                for (Operand operand : operands) {
                    if (isGlobalVariable(operand)) {
                        usedGlobalVariableInstructions.add(instruction);
                    }
                }
            }
        }
        return usedGlobalVariableInstructions;
        
    }

    private boolean isGlobalVariable(Operand operand) {
        for (GlobalVariable globalVariable : globalVariables) {
            if (operand.toString().contains(globalVariable.getName())) {
                return true;
            }            
        }
        return false;
    }
    private boolean isArguments(Operand operand) {

        if (operand.toString().contains("arg_")) {
            return true;
        }
        return false;
    }

    

    private void initGlobalVariables() {
        GlobalVariablesManager gvm = module.getGlobalVariablesManager();

        globalVariables = gvm.getVariables();

    }

    private Set<Instruction> findArgumentInstructions() {

        HashSet<Instruction> usedArgumentInstructions = new HashSet<Instruction>();

        FlowGraph flowGraph = null;
        if (function != null) {
            
            //TODO
            
            try {
                flowGraph = function.getGraph();
            }catch(Exception e)
            {
                return usedArgumentInstructions;
            }
            finally {
            }

        }
        List<BasicBlock> basicBlocks = flowGraph.getNodes();
        for (BasicBlock bb : basicBlocks) {
            List<Instruction> instructions = bb.getInstructions();
            for (Instruction instruction : instructions) {
                List<Operand> operands = instruction.getOperands();
                for (Operand operand : operands) {
                    if (isArguments(operand)) {
                        usedArgumentInstructions.add(instruction);
                    }
                }
            }
        }
        return usedArgumentInstructions;
    }

    private Set<String> findUsedOperands() {

        HashSet<String> usedOperands = new HashSet<String>();

        FlowGraph flowGraph = null;
        if (function != null) {
            // TODO
            try {
                if(!function.isLoaded())    function.load();
                flowGraph = function.getGraph();
            } catch (Exception e) {
                System.out.println("findUsedOperands() ! : "+function.getAddress());
                System.out.println(e);
                return usedOperands;
            } finally {
            }

        }

        List<BasicBlock> basicBlocks = null;
        if (flowGraph != null) {
            basicBlocks = flowGraph.getNodes();
        }

        if (basicBlocks == null) {
            return usedOperands;
        }

        for (BasicBlock bb : basicBlocks) {
            List<Instruction> instructions = bb.getInstructions();

            for (Instruction instruction : instructions) {
                List<Operand> operands = instruction.getOperands();

                for (Operand operand : operands) {
                    usedOperands.add(operand.toString());
                }
            }
        }

        return usedOperands;
    }

    private void findUsedGlobalVariables() {
        for (String operand : usedOperands) {
            for (GlobalVariable globalVariable : globalVariables) {
                if (operand.contains(globalVariable.getName())) {
                    System.out.println("global : "+globalVariable.getName());
                    usedGlobalVariables.add(operand);
                }
            }
        }
    }

    private void findUsedLocalVariables() {
        
        for (String operand : usedOperands) {
            if (operand.contains("var_") || operand.contains("loc_")) {
                String variable = stringOfLocalVariable(operand);
               
                usedLocalVariables.add(variable);
            }
        }
        
    }

    private String stringOfLocalVariable(String operand) {
        String localVariable = operand.toString();

        while (!(localVariable.startsWith("var_") || localVariable.startsWith("loc_"))) {
            localVariable = localVariable.substring(1, localVariable.length());
            if (localVariable.length() == 0) {
                break;
            }
        }

        if (localVariable.length() == 0) {
            System.out.println("error : InterBBAnalysis - stringOfLocalVariable() - localVariable's length is 0\n");
        }
        return localVariable;

    }


    private void findUsedArguments() {
        for (String operand : usedOperands) {
            if (operand.contains("arg_")) {
                String argument = getStringOfArguments(operand);
                usedArguments.add(argument);
                
            }
        }
    }

    private String getStringOfArguments(String operand) {
        String argument = operand.substring(4, operand.length() - 1);

        while (!argument.startsWith("arg_")) {
            argument = argument.substring(1, argument.length());
        }

        if (argument.length() == 0) {
            LogConsole.log("error : InterBBAnalysis - stringOfArguments() - argument length is 0");
        }
        return argument;
    }

    public Set<Instruction> getUsedArgumentInstructions() {
        return usedArgumentInstructions;
    }

    public void setUsedArgumentInstructions(Set<Instruction> usedArgumentInstructions) {
        this.usedArgumentInstructions = usedArgumentInstructions;
    }

}
