package helper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntLoadDataException;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import com.google.security.zynamics.binnavi.API.reil.OperandType;
import com.google.security.zynamics.binnavi.API.reil.ReilBlock;
import com.google.security.zynamics.binnavi.API.reil.ReilFunction;
import com.google.security.zynamics.binnavi.API.reil.ReilGraph;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import data.ReilInstructionResolve;

public class ArgumentScanner {

    public static Set<Map<Long, InstructionGraphNode>> ArgumentScan(Function function, VariableFinder vf) throws InternalTranslationException {

        Set<Map<Long, InstructionGraphNode>> registerArguments = new HashSet<>();
        Set<String> definedRegister = new HashSet<>();

        
        
        Function curFunc = function;
        if (curFunc == null) {
            System.out.println("error - argumentScan() : function is null!!");
            return null;
        }
                
        loadFunction(curFunc);
        ReilFunction curReilFunc = curFunc.getReilCode();
        InstructionGraph graph = InstructionGraph.create(curReilFunc.getGraph());

        List<InstructionGraphNode> nodes = graph.getNodes();
        for (InstructionGraphNode node : nodes) {
            ReilInstruction reilInst = node.getInstruction();
            // src
            List<ReilOperand> srcs = ReilInstructionResolve.resolveReilInstructionSrc(reilInst);
            
            if(isUseWitoutDef(definedRegister, reilInst, srcs, curFunc)){   
                
                Map<Long, InstructionGraphNode> registerArgument =  CrashSourceAdder.getSrcNAddress(graph, reilInst.getAddress().toLong()%0x100, InterProcedureMode.NORMAL, vf);
                registerArguments.add(registerArgument);
            }
            
            // dest
            addDefinedRegisters(definedRegister, reilInst);
        }

        return registerArguments;
    }

    private static void loadFunction(Function curFunc) {
        try {
            if (!curFunc.isLoaded()) {
                curFunc.load();
            }
        } catch (CouldntLoadDataException e1) {
            e1.printStackTrace();
        } catch (Exception e1) {
            System.out.println("dubugging ");
        }
    }

    private static void addDefinedRegisters(Set<String> definedRegister, ReilInstruction reilInst) {

        if (ReilInstructionResolve.isDefinitionInstruction(reilInst)) {
            List<ReilOperand> dests = ReilInstructionResolve.resolveReilInstructionDest(reilInst);
            for (ReilOperand reilOperand : dests) {
                if (canBeArgumentRegister(reilOperand)) {
                    definedRegister.add(reilOperand.getValue());
                }
            }
        }
    }

    private static boolean isUseWitoutDef(Set<String> definedRegister,
            ReilInstruction reilInst, List<ReilOperand> srcs, Function curFunc) {

        Set<Map<Address, String>> arguments = new HashSet<>();

        Instruction nativeInst = ReilInstructionResolve.findNativeInstruction(curFunc, reilInst.getAddress());
        
        for (ReilOperand operand : srcs) {
            OperandType type = operand.getType();
            if ((type == OperandType.REGISTER) && canBeArgumentRegister(operand)) {
                
                nativeInst = ReilInstructionResolve.findNativeAboutReilInstruction(curFunc, reilInst.getAddress());
                if("push".equals(nativeInst.getMnemonic()) || "PUSH".equals(nativeInst.getMnemonic()))
                {
                    continue;
                }
                
                if (useWithOutDef(definedRegister, operand)) {
                    return true;            
                }
            }
        }
        return false;
    }

    private static boolean useWithOutDef(Set<String> definedRegister, ReilOperand operand) {
        return definedRegister.contains(operand.getValue());
    }
  
    private static boolean canBeArgumentRegister(ReilOperand operand) {
        String operand_str = operand.getValue();

        // temp
        if (operand_str.charAt(0) == 't') {
            return false;
        }
        if (operand_str.charAt(0) == 'N') {
            return false;
        }
        if (operand_str.charAt(0) == 'Z') {
            return false;
        }
        if (operand_str.charAt(0) == 'O') {
            return false;
        }
        if (operand_str.charAt(0) == 'V') {
            return false;
        }
        if (operand_str.charAt(0) == 'C') {
            return false;
        }

        if (operand_str.length() > 1) {
            
            if (operand_str.charAt(0) == 'D') {
                if (operand_str.charAt(1) == 'F') {
                    return false;
                }
            }
            
            if (operand_str.charAt(0) == 'S') {
                if (operand_str.charAt(1) == 'P') {
                    return false;
                }
            }
            
            if (operand_str.charAt(0) == 'L') {
                if (operand_str.charAt(1) == 'R') {
                    return false;
                }
            }

            if (operand_str.charAt(1) > '4' && operand_str.charAt(1) <= '9') {
                return false;
            }
        }
        if (operand_str.length() > 2) {

            if (operand_str.charAt(2) == 'p') {
                if (operand_str.charAt(1) == 's') {
                    if (operand_str.charAt(0) == 'e') {
                        return false;
                    }
                }
            }

            if (operand_str.charAt(2) == 'p') {
                if (operand_str.charAt(1) == 'b') {
                    if (operand_str.charAt(0) == 'e') {
                        return false;
                    }
                }
            }

            if (operand_str.charAt(0) == 'R') {

                if (operand_str.charAt(1) == '1' && isDigit(operand_str, 2)) {
                    return false;
                }
            }
        }

        return true;
    }

    private static boolean isDigit(String operand_str, int position) {
        return operand_str.charAt(position) <= '9' && operand_str.charAt(position) >= '0';
    }

    public static void print(Set<Map<Long, InstructionGraphNode>> scannedArgument) {

        for (Map<Long, InstructionGraphNode> map : scannedArgument) {
            for (Long addr : map.keySet()) {
                System.out.println("0x" + addr.toHexString(addr) + " : " + map.get(addr));
            }
        }
    }
}
