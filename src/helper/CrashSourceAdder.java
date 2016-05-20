package helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
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
        if (interProcedureAnalysisMode == InterProcedureMode.NORMAL) {
            return getCrashPointSrcInstruction(graph, crashAddr);
        }
        else if(interProcedureAnalysisMode == InterProcedureMode.FUNCTIONAnalysis)
        {
            return getArgumentInstruction(graph,crashAddr);
        }
        return getCrashPointSrcInstruction(graph, crashAddr);
        
    }

    private static InstructionGraphNode getArgumentInstruction(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr) {
        
        
        
        //TODO
        List<InstructionGraphNode> originalList = graph.getNodes();
        InstructionGraphNode crashInstruction = null;
        boolean addFlag = false;

        long preInstAddr = 0x00;
        ReilOperand toBeAddOperand = null;
        for (InstructionGraphNode inst : originalList) {
            long instAddr = inst.getInstruction().getAddress().toLong();

            if (addFlag && instAddr % 0x100 == 0) {
                Address addr = new Address(preInstAddr + 1);
                crashInstruction = makeCrashSrcInstruction(addr, toBeAddOperand);
                addFlag = false;
                break;
            }

            if (instAddr % 0x100 == 0 && instAddr / 0x100 == crashAddr) {
                addFlag = true;
                toBeAddOperand = inst.getInstruction().getFirstOperand();
            }
            preInstAddr = instAddr;

        }
        return crashInstruction;
    }

    private static InstructionGraphNode getCrashPointSrcInstruction(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr) {
        List<InstructionGraphNode> originalList = graph.getNodes();
        InstructionGraphNode crashInstruction = null;
        boolean addFlag = false;

        long preInstAddr = 0x00;
        ReilOperand toBeAddOperand = null;
        for (InstructionGraphNode inst : originalList) {
            long instAddr = inst.getInstruction().getAddress().toLong();

            if (addFlag && instAddr % 0x100 == 0) {
                Address addr = new Address(preInstAddr + 1);
                crashInstruction = makeCrashSrcInstruction(addr, toBeAddOperand);
                addFlag = false;
                break;
            }

            if (instAddr % 0x100 == 0 && instAddr / 0x100 == crashAddr) {
                addFlag = true;
                toBeAddOperand = inst.getInstruction().getFirstOperand();
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

    public static Set<Map<InstructionGraphNode, Long> > getSrcNAddress(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr, InterProcedureMode analysisMode) {
        
        
        Set< Map<InstructionGraphNode,Long>  > toBeAddedSrcNAddresses = new HashSet<>();
        
        switch(analysisMode){
            case NORMAL:
                return getSrcNAddress_Get(graph, crashAddr, analysisMode, toBeAddedSrcNAddresses);
            case FUNCTIONAnalysis:
                break;
            case GVAnalysis :
                break;
            default:
        }
        System.out.println("error : getSrcNAddress() - It is not correct interprocedure Analysis Mode");
        System.exit(-1);
        return null;
    }
    private static Set<Map<InstructionGraphNode, Long>> getSrcNAddress_Get(ILatticeGraph<InstructionGraphNode> graph,
            Long crashAddr, InterProcedureMode analysisMode,
            Set<Map<InstructionGraphNode, Long>> toBeAddedSrcNAddresses) {
        InstructionGraphNode crashSrcNode = CrashSourceAdder.getInstruction(graph, crashAddr, analysisMode);
        long toBeInsertedAddress = CrashSourceAdder.getNextReilAddrOfCrash(graph, crashAddr);
        Map<InstructionGraphNode, Long> toBeAddedSrcNAddress = new HashMap<InstructionGraphNode, Long>();
        toBeAddedSrcNAddress.put(crashSrcNode, toBeInsertedAddress);
        toBeAddedSrcNAddresses.add(toBeAddedSrcNAddress);
        
        return toBeAddedSrcNAddresses;
    }
}
