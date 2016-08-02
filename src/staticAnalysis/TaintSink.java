package staticAnalysis;

import java.util.List;
import java.util.Map;

import com.google.security.zynamics.binnavi.API.disassembly.Instruction;

interface TaintSink {

    boolean isTaintSink();
    Map<Instruction, List<Instruction>> getExploitArmPaths();
    
    int getTotal_e_count();
    int getTotal_pe_count();
}
