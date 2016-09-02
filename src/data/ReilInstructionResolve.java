package data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntLoadDataException;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.FunctionType;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.reil.OperandType;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

public class ReilInstructionResolve {

	public enum ReilCase{STORE, LOAD, ARITHMETIC, LOGIC};
	
	private final static Map<String, ReilInstIndex> instStringToInstValue = new HashMap<String, ReilInstIndex>();

	static {
		instStringToInstValue.put("add", ReilInstIndex.ADD);
		instStringToInstValue.put("and", ReilInstIndex.AND);
		instStringToInstValue.put("bisz", ReilInstIndex.BISZ);
		instStringToInstValue.put("bsh", ReilInstIndex.BSH);
		instStringToInstValue.put("div", ReilInstIndex.DIV);
		instStringToInstValue.put("jcc", ReilInstIndex.JCC);
		instStringToInstValue.put("ldm", ReilInstIndex.LDM);
		instStringToInstValue.put("mod", ReilInstIndex.MOD);
		instStringToInstValue.put("mul", ReilInstIndex.MUL);
		instStringToInstValue.put("nop", ReilInstIndex.NOP);
		instStringToInstValue.put("or", ReilInstIndex.OR);
		instStringToInstValue.put("stm", ReilInstIndex.STM);
		instStringToInstValue.put("str", ReilInstIndex.STR);
		instStringToInstValue.put("sub", ReilInstIndex.SUB);
		instStringToInstValue.put("undef", ReilInstIndex.UNDEF);
		instStringToInstValue.put("unkn", ReilInstIndex.UNKNOWN);
		instStringToInstValue.put("xor", ReilInstIndex.XOR);
	}
//TODO do something using this!!!
	public static List<ReilOperand> resolveReilInstructionSrc(
			InstructionGraphNode inst) {
		List<ReilOperand> src = new ArrayList<ReilOperand>();

		switch (instStringToInstValue.get(inst.getInstruction().getMnemonic())) {
		case ADD: // addition
		case AND: // binary and
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		case BISZ: // boolean is zero
			src.add(inst.getInstruction().getFirstOperand());
			break;
		case BSH: // binary shift
		case DIV: // unsigned division
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		case JCC:
			// in case of JCC, it is impossible for the first operand to become
			// SUB_ADDRESS type
			// So we don't need to consider the exception cases
			if (inst.getInstruction().getFirstOperand().getType() == OperandType.REGISTER)
				src.add(inst.getInstruction().getFirstOperand());
			if (inst.getInstruction().getThirdOperand().getType() == OperandType.REGISTER)
				src.add(inst.getInstruction().getThirdOperand());
			break;
		case LDM:
			src.add(inst.getInstruction().getFirstOperand());
			break;
		case MOD: // modulo
		case MUL: // unsigned multiplication
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		case NOP: // no operation
			break;
		case OR: // bitwise Or
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		case STM: // store to memory
		case STR: // store to register
			src.add(inst.getInstruction().getFirstOperand());
			break;
		case SUB: // subtract
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		// in source case, we don't need to consider anything
		case UNDEF:
			// Nothing
			break;
		case UNKNOWN: // unknown operation ( placeholder instruction )
			break;
		case XOR:
			src.add(inst.getInstruction().getFirstOperand());
			src.add(inst.getInstruction().getSecondOperand());
			break;
		default: // Exception
			// There are no more instructions than these cases
			// so we don't handle anything here
			break;
		}

		return src;
	}

	public static List<ReilOperand> resolveReilInstructionDest(
			InstructionGraphNode inst) {
		List<ReilOperand> dest = new ArrayList<ReilOperand>();

		switch (instStringToInstValue.get(inst.getInstruction().getMnemonic())) {
		case ADD: // addition
		case AND: // binary and
		case BISZ: // boolean is zero
		case BSH: // binary shift ( if the second operand is positive, shift
					// right, vice versa
		case DIV: // unsgigned division
			dest.add(inst.getInstruction().getThirdOperand());
			break;
		case JCC: // jump conditional
			// Nothing
			break;
		case LDM: // load from memory
		case MOD: // modulo operation
		case MUL: // unsigned multiplication
			dest.add(inst.getInstruction().getThirdOperand());
			break;
		case NOP: // no operation
			break;
		case OR: // bitwise or
			// in case of the STM and STR,
			// the size of the first operand determines the number of bytes to
			// be written to memory
		case STM: // store to memory
		case STR: // store to register
		case SUB: // subtract
			dest.add(inst.getInstruction().getThirdOperand());
			break;
		case UNDEF: // undefined register
			// This instruction means that the third operand can't be used until
			// it is updated
			// So in def-use chain, if def instruction is the UNDEF, we need to
			// get rid of the chain.
			dest.add(inst.getInstruction().getThirdOperand());
			break;
		case UNKNOWN: // unknown operation ( placeholder instruction )
			break;
		case XOR: // bitwise exclusive Or
			dest.add(inst.getInstruction().getThirdOperand());
			break;
		default: // Exception
			// There are no more instruction than these cases
			// so we don't handle anything here
			break;
		}

		return dest;
	}

	public static boolean isLoadToRegister(InstructionGraphNode inst) {
		ReilInstIndex instIndex = instStringToInstValue.get(inst
				.getInstruction().getMnemonic());
		if (instIndex == ReilInstIndex.LDM) {
			return true;
		}

		return false;
	}

	public static boolean isStoreToMemory(InstructionGraphNode inst) {
		ReilInstIndex instIndex = instStringToInstValue.get(inst
				.getInstruction().getMnemonic());
		if (instIndex == ReilInstIndex.STM) {
			return true;
		}

		return false;
	}

	public static boolean isLiteralDirectAccess(InstructionGraphNode inst) {
		if (isLoadToRegister(inst)) {
			if (ReilHelpers.isRegister(inst.getInstruction().getFirstOperand())) {
				return false;
			} else
				return true;
		} else if (isStoreToMemory(inst)) {
			if (ReilHelpers.isRegister(inst.getInstruction().getThirdOperand())) {
				return false;
			} else
				return true;
		}
		// In case of other instruction like ADD, it is impossible
		else
			return false;
	}

	public static boolean isRegisterIndirectAccess(InstructionGraphNode inst) {
		if (isLoadToRegister(inst)) {
			if (ReilHelpers.isRegister(inst.getInstruction().getFirstOperand())) {
				return true;
			} else
				return false;
		} else if (isStoreToMemory(inst)) {
			if (ReilHelpers.isRegister(inst.getInstruction().getThirdOperand())) {
				return true;
			} else
				return false;
		}
		// In case of other instruction like ADD, it is impossible
		else
			return false;
	}

	
	
	public static boolean isSameDefinition(InstructionGraphNode def1,
			InstructionGraphNode def2) {
		// To do
		if (ReilInstructionResolve.isStoreToMemory(def1)) {
			if (ReilInstructionResolve.isStoreToMemory(def2)) {
				// After completing VSA, we need to add some code referencing
				// VSA states
				return false;
			}
			// In case that def2 is load or arithmetic
			else {
				return false;
			}
		} else if (ReilInstructionResolve.isLoadToRegister(def1)) {
			if (ReilInstructionResolve.isStoreToMemory(def2)) {
				return false;
			}
			// In case that def2 is load or arithmetic
			else {
				for (ReilOperand dest1 : resolveReilInstructionDest(def1)) {
					for (ReilOperand dest2 : resolveReilInstructionDest(def2)) {
						return dest1.getValue().equals(dest2.getValue());
					}
				}
			}
		}
		// In case of arithmetic
		else {
			if (ReilInstructionResolve.isStoreToMemory(def2)) {
				return false;
			}
			// In case that def2 is load or arithmetic
			else {
				for (ReilOperand dest1 : resolveReilInstructionDest(def1)) {
					for (ReilOperand dest2 : resolveReilInstructionDest(def2)) {
						return dest1.getValue().equals(dest2.getValue());
					}
				}
			}
		}

		return false;
	}

	public static Instruction findNativeInstruction(Function func, long address) {

		if (func.isLoaded()) {
			for (BasicBlock bb : func.getGraph().getNodes()) {
				for (Instruction inst : bb.getInstructions()) {
					if (inst.getAddress().toLong() == address) {
						return inst;
					}
				}
			}
		}

		return null;
	}

	public static Instruction findNativeInstruction(Function func,	Address address) {

		if (func.isLoaded()) {
			for (BasicBlock bb : func.getGraph().getNodes()) {
				for (Instruction inst : bb.getInstructions()) {
					if (inst.getAddress().toLong() == address.toLong()) {
						
						return inst;
					}
				}
			}
		}

		return null;
	}

	public static ReilInstIndex getKindInst(InstructionGraphNode inst) {
		// If stm, return -1
		// if ldm, return 1
		// else 0
		ReilInstIndex instIndex = instStringToInstValue.get(inst
				.getInstruction().getMnemonic());
		if (instIndex == ReilInstIndex.LDM)
			return ReilInstIndex.LDM;

		if (instIndex == ReilInstIndex.STM)
			return ReilInstIndex.STM;
	
		return ReilInstIndex.OTHERS;
	}
	
	public static ReilInstIndex getReilCase(InstructionGraphNode inst){
		ReilInstIndex instIndex = 
				instStringToInstValue.get(inst.getInstruction().getMnemonic());

		return instIndex;
	}
	
	public static ReilInstruction changeDest(ReilInstruction ori, String dest)
	{

		ReilOperand operand = new ReilOperand(ori.getThirdOperand().getSize(), dest);
		ReilInstruction ri= new ReilInstruction(ori.getAddress(),
												ori.getMnemonic(), ori.getFirstOperand(), 
												ori.getSecondOperand(), operand); 
		return ri;
	}
	
	
	
	

}
