package staticAnalysis;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Module;

public class InterProcedureAnalysis {

    private FunctionCallAnalysis functionCallAnalysis ;
    private GlobalVariableAnalysis globalVariableAnalysis;
    
    public InterProcedureAnalysis(Module module, Function curFunc){
    
        functionCallAnalysis = new FunctionCallAnalysis(module, curFunc);
        globalVariableAnalysis = new GlobalVariableAnalysis(module, curFunc);
    }

    public boolean needAnalysis() {
        
        boolean needGlobalVariableAnalysis = !globalVariableAnalysis.dontUseGlobalVariable();        
        
        if(needGlobalVariableAnalysis)
        {
            System.out.println("need global Variable Analysis");
        }
        return (needGlobalVariableAnalysis);
    }

    
}
