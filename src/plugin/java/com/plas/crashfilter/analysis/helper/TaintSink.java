package plugin.java.com.plas.crashfilter.analysis.helper;

import com.google.security.zynamics.binnavi.API.disassembly.Instruction;

import java.util.List;
import java.util.Map;

public interface TaintSink {

    boolean isTaintSink();
    Map<Instruction, List<Instruction>> getExploitArmPaths();
    
    int getTotal_e_count();
    int getTotal_pe_count();
}
