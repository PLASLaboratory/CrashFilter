package staticAnalysis;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.debug.Register;
import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import com.google.security.zynamics.binnavi.API.reil.OperandType;
import com.google.security.zynamics.binnavi.API.reil.ReilBlock;
import com.google.security.zynamics.binnavi.API.reil.ReilGraph;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;

import data.ReilInstructionResolve;

public class ArgumentScanner {

    public Set<Map<Address, ReilOperand>> scan(Function function) throws InternalTranslationException {

        Set<Map<Address, ReilOperand>> registerArguments = new HashSet<>();
        Set<ReilOperand> definedRegister = new HashSet<>();

        List<BasicBlock> nodes = function.getGraph().getNodes();

        for (BasicBlock node : nodes) {
            ReilGraph reilGraph = node.getReilCode();
            for (ReilBlock reilBlock : reilGraph.getNodes()) {
                for (ReilInstruction reilInst : reilBlock.getInstructions()) {                   
                    //for all Reil Instruction                    
                    if (ReilInstructionResolve.isDefinitionInstruction(reilInst)) {                        
                        
                        //src
                        List<ReilOperand> srcs = ReilInstructionResolve.resolveReilInstructionSrc(reilInst);
                        Map<Address, ReilOperand> registerArgument = getUseWitoutDef(definedRegister, reilInst, srcs);
                        registerArguments.add(registerArgument);                        
                        
                        //dest
                        addDefinedRegisters(definedRegister, reilInst);

                    }
                }
            }
        }

        return registerArguments;
    }

    private void addDefinedRegisters(Set<ReilOperand> definedRegister, ReilInstruction reilInst) {
        List<ReilOperand> dests = ReilInstructionResolve.resolveReilInstructionDest(reilInst);
        
        for (ReilOperand reilOperand : dests) {
            if (ReilInstructionResolve.isDefinitionInstruction(reilInst)) {
                definedRegister.add(reilOperand);
            }
        }
    }

    private Map<Address, ReilOperand> getUseWitoutDef(Set<ReilOperand> definedRegister, ReilInstruction reilInst,
            List<ReilOperand> srcs) {
        Map<Address, ReilOperand> registerArgument = new HashMap<>();

        for (ReilOperand operand : srcs) {
            OperandType type = operand.getType();
            if ((type == OperandType.REGISTER) && isNativeRegister(operand)) {
                if (definedRegister.contains(operand)) {

                    registerArgument.put(reilInst.getAddress(), operand);

                }
            }
        }
        return registerArgument;
    }

    private boolean isNativeRegister(ReilOperand operand) {
        String operand_str = operand.getValue();

        if (operand_str.charAt(0) == 't') {
            return false;
        }

        return true;
    }
}
