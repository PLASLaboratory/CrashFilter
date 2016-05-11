package staticAnalysis;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Module;

import helper.FunctionCallManager;

public class InterBBAnalysis {

    FunctionCallManager functionCallManager ;
    
    public InterBBAnalysis(Module module, Function curFunc){
    
        functionCallManager = new FunctionCallManager(module, curFunc);
    }
    
    public boolean needAnalysis() {   
        return !functionCallManager.dontHaveToAnalysis();
    }
    
}
