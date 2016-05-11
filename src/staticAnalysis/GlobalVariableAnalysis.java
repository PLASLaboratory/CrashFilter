package staticAnalysis;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Module;

import helper.VariableFinder;

public class GlobalVariableAnalysis {
    private Function currentFunction;
    private Module module;
    private VariableFinder variableFinder;

    public GlobalVariableAnalysis(Module module, Function function) {
        
        currentFunction = function;
        variableFinder = new VariableFinder(module, currentFunction);
        this.module = module;

    }
    
    public boolean dontUseGlobalVariable() {
        return variableFinder.getUsedGlobalVariables().size() == 0;
    }
    
    
}
