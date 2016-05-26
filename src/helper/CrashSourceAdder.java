package helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.reil.OperandSize;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

public class CrashSourceAdder {

    
    
    public static List<InstructionGraphNode> getInstructionlist(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr) {
        List<InstructionGraphNode> originalList = graph.getNodes();
        List<InstructionGraphNode> InstructionGraphNodes = new ArrayList<InstructionGraphNode>();
        InstructionGraphNode crashInstruction = null;
        boolean addFlag = false;

        long preInstAddr = 0x00;
        ReilOperand toBeAddOperand = null;
        for (InstructionGraphNode inst : originalList) {
            long instAddr = inst.getInstruction().getAddress().toLong();

            if (addFlag && instAddr % 0x100 == 0) {
                Address addr = new Address(preInstAddr + 1);
                crashInstruction = makeCrashSrcInstruction(addr, toBeAddOperand);
                InstructionGraphNodes.add(crashInstruction);
                addFlag = false;
            }

            if (instAddr % 0x100 == 0 && instAddr / 0x100 == crashAddr) {
                addFlag = true;
                toBeAddOperand = inst.getInstruction().getFirstOperand();
            }
            preInstAddr = instAddr;

            InstructionGraphNodes.add(inst);
        }
        return InstructionGraphNodes;
    }

    public static InstructionGraphNode getInstruction(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr,InterProcedureMode interProcedureAnalysisMode) {
        
        System.out.println("Ddddddddddddddddddddd");
        
       switch(interProcedureAnalysisMode)
       {
           case NORMAL:
               return getCrashPointSrcInstruction(graph, crashAddr);
           case FUNCTIONAnalysis:
               return getArgumentInstruction(graph,crashAddr);
           case GVAnalysis:
               return null;
           default:
               return null;
               
       }
        

        
    }



    private static InstructionGraphNode getArgumentInstruction(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr) {
        // TODO Auto-generated method stub
        return null;
    }

    private static InstructionGraphNode getCrashPointSrcInstruction(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr) {
        
        List<InstructionGraphNode> originalList = graph.getNodes();
        InstructionGraphNode crashInstruction = null;
        boolean addFlag = false;

        long preInstAddr = 0x00;
        ReilOperand toBeAddedOperand = null;
        for (InstructionGraphNode inst : originalList) {
            long instAddr = inst.getInstruction().getAddress().toLong();

            if (addFlag && instAddr % 0x100 == 0) {
                Address addr = new Address(preInstAddr + 1);
                crashInstruction = makeCrashSrcInstruction(addr, toBeAddedOperand);
                addFlag = false;
                break;
            }

            if (instAddr % 0x100 == 0 && instAddr / 0x100 == crashAddr) {
                addFlag = true;
                toBeAddedOperand = inst.getInstruction().getFirstOperand();
            }
            preInstAddr = instAddr;

        }
        return crashInstruction;
    }

    public static long getNextReilAddrOfCrash(ILatticeGraph<InstructionGraphNode> graph, Long crashAddr) {
        List<InstructionGraphNode> originalList = graph.getNodes();
        boolean addFlag = false;

        long preInstAddr = 0x00;
        ReilOperand toBeAddOperand = null;

        long nextAddrOfCrash = 0;

        for (InstructionGraphNode inst : originalList) {
            long instAddr = inst.getInstruction().getAddress().toLong();

            if (addFlag && instAddr % 0x100 == 0) {
                Address addr = new Address(preInstAddr + 1);
                makeCrashSrcInstruction(addr, toBeAddOperand);
                addFlag = false;
                nextAddrOfCrash = inst.getInstruction().getAddress().toLong();
                break;
            }

            if (instAddr % 0x100 == 0 && instAddr / 0x100 == crashAddr) {
                addFlag = true;
                toBeAddOperand = inst.getInstruction().getFirstOperand();
            }
            preInstAddr = instAddr;

        }
        return nextAddrOfCrash;
    }

    private static InstructionGraphNode makeCrashSrcInstruction(Address crashAddr, ReilOperand reilOperand) {
        ReilOperand firstOperand = new ReilOperand(OperandSize.OPERAND_SIZE_DWORD, "EMPTY");
        ReilOperand secondOperand = new ReilOperand(OperandSize.OPERAND_SIZE_DWORD, "EMPTY");
        ReilOperand destOperand = reilOperand;

        ReilInstruction reilInstruction = new ReilInstruction(crashAddr, "str", firstOperand, secondOperand,
                destOperand);
        InstructionGraphNode inst = new InstructionGraphNode(reilInstruction);
        return inst;
    }

    public static  Map<Long, InstructionGraphNode> getSrcNAddress(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr, InterProcedureMode analysisMode,VariableFinder vf) {
        
        switch(analysisMode){
            case NORMAL:
                return getSetOfSrcNAddress(graph, crashAddr, analysisMode);
            case FUNCTIONAnalysis:
                return getSetOfArgumentsNAddress(graph,  analysisMode, vf);                
            case GVAnalysis :
                break;
            default:
        }
        System.out.println("error : getSrcNAddress() - It is not correct interprocedure Analysis Mode");
        System.exit(-1);
        return null;
    }
    
    private static Map< Long, InstructionGraphNode> getSetOfArgumentsNAddress(
            ILatticeGraph<InstructionGraphNode> graph, InterProcedureMode analysisMode, VariableFinder vf) {
        
        //TODO
        
        Set<Instruction> usedArgumentInstructions = vf.getUsedArgumentInstructions();
        Map<Long, InstructionGraphNode> toBeAddedSrcNAddress = new HashMap<>();
        
        for(Instruction inst : usedArgumentInstructions)
        {
            Long argumentAddr = inst.getAddress().toLong();
            InstructionGraphNode crashSrcNode = getInstruction(graph, argumentAddr, analysisMode);
            long toBeInsertedAddress = getNextReilAddrOfCrash(graph, argumentAddr);
            
            toBeAddedSrcNAddress.put(toBeInsertedAddress, crashSrcNode);
        }
        
        return toBeAddedSrcNAddress;
    }

    private static  Map<Long, InstructionGraphNode> getSetOfSrcNAddress(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr, InterProcedureMode analysisMode) {
        
        InstructionGraphNode crashSrcNode = getInstruction(graph, crashAddr, analysisMode);
        long toBeInsertedAddress = getNextReilAddrOfCrash(graph, crashAddr);
        Map<Long, InstructionGraphNode> toBeAddedSrcNAddress = new  HashMap<>();
        toBeAddedSrcNAddress.put(toBeInsertedAddress, crashSrcNode);
        
        return toBeAddedSrcNAddress;
    }
}
