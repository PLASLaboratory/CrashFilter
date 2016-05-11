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

    private  Module module;
    private  Function function;

    private List<GlobalVariable> globalVariables = new ArrayList<GlobalVariable>();

    private Set<String> usedGlobalVariables = new HashSet<String>();
    private Set<String> usedLocalVariables = new HashSet<String>();
    private Set<String> usedArguments = new HashSet<String>();
    private Set<String> usedOperands = new HashSet<String>();

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

    }

    private void initGlobalVariables() {
        GlobalVariablesManager gvm = module.getGlobalVariablesManager();
        gvm.getVariables();

        globalVariables = gvm.getVariables();
        System.out.println("global : \n" + globalVariables);
    }

    private Set<String> findUsedOperands() {

        HashSet<String> usedOperands = new HashSet<String>();

        FlowGraph flowGraph = function.getGraph();
        List<BasicBlock> basicBlocks = flowGraph.getNodes();
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
        //TODO
        for (String operand : usedOperands) {
            for (GlobalVariable globalVariable : globalVariables) {
                if (operand.contains(globalVariable.getName())) {
                    System.out.println("finded global variable : " + globalVariable.getName());
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
        String localVariable = operand.substring(4, operand.length() - 1);

        while (!(localVariable.startsWith("var_") || localVariable.startsWith("loc_"))) {
            localVariable = localVariable.substring(1, localVariable.length());
        }

        if (localVariable.length() == 0) {
            LogConsole.log("error : InterBBAnalysis - stringOfLocalVariable() - localVariable's length is 0");
        }
        return localVariable;

    }

    private void findUsedArguments() {
        for (String operand : usedOperands) {
            if (operand.contains("arg_")) {
                String argument = getStringOfArguments(operand);
                usedArguments.add(argument);
                System.out.println("argument : " + argument);
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

}
