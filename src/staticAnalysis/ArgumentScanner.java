package staticAnalysis;

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

    public static Set<Map<Address, ReilOperand>> ArgumentScan(Function function) throws InternalTranslationException {

        Set<Map<Address, ReilOperand>> registerArguments = new HashSet<>();
        Set<ReilOperand> definedRegister = new HashSet<>();

        Function curFunc = function;
        if(curFunc == null)
        {
            System.out.println("error - argumentScan() : function is null!!");
            return null;
        }
       
        loadFunction(curFunc);
        ReilFunction curReilFunc = curFunc.getReilCode();
        InstructionGraph graph = InstructionGraph.create(curReilFunc.getGraph());
        
        List<InstructionGraphNode> nodes = graph.getNodes();
        for(InstructionGraphNode node : nodes)
        {
            ReilInstruction reilInst = node.getInstruction();
            
            //src
            List<ReilOperand> srcs = ReilInstructionResolve.resolveReilInstructionSrc(reilInst);                        
            registerArguments.addAll(getUseWitoutDef(definedRegister, reilInst, srcs));                       
            
            //dest
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

    private static void addDefinedRegisters(Set<ReilOperand> definedRegister, ReilInstruction reilInst) {
        List<ReilOperand> dests = ReilInstructionResolve.resolveReilInstructionDest(reilInst);
        
        for (ReilOperand reilOperand : dests) {
            if (ReilInstructionResolve.isDefinitionInstruction(reilInst)) {
                definedRegister.add(reilOperand);
            }
        }
    }

    private static Set<Map<Address, ReilOperand>> getUseWitoutDef(Set<ReilOperand> definedRegister, ReilInstruction reilInst,
            List<ReilOperand> srcs) {
        

        Set<Map<Address, ReilOperand>> arguments = new HashSet<>();
        
        for (ReilOperand operand : srcs) {
            OperandType type = operand.getType();
            if ((type == OperandType.REGISTER) && isNativeRegister(operand)) {
                if (definedRegister.contains(operand)) {
                    Map<Address, ReilOperand> registerArgument = new HashMap<>();
                    registerArgument.put(reilInst.getAddress(), operand);
                    arguments.add(registerArgument);
                }
            }
        }
        return arguments;
    }

    private static boolean isNativeRegister(ReilOperand operand) {
        String operand_str = operand.getValue();

        if (operand_str.charAt(0) == 't') {
            return false;
        }

        return true;
    }

    public static void print(Set<Map<Address, ReilOperand>> scannedArgument) {

        for (Map<Address, ReilOperand> map : scannedArgument) {
            for (Address addr : map.keySet()) {
                System.out.println("0x" + addr.toHexString() + " : " + map.get(addr));
            }
        }
    }
}
