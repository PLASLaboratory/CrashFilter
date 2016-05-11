package staticAnalysis;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Module;

public class InterBBAnalysis {

    private FunctionCallAnalysis functionCallAnalysis ;
    private GlobalVariableAnalysis globalVariableAnalysis;
    
    public InterBBAnalysis(Module module, Function curFunc){
    
        functionCallAnalysis = new FunctionCallAnalysis(module, curFunc);
        globalVariableAnalysis = new GlobalVariableAnalysis(module, curFunc);
    }

    public boolean needAnalysis() {
        // TODO Auto-generated method stub
        return false;
    }

    
}
