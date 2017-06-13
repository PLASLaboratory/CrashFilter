package plugin.java.com.plas.crashfilter.analysis.ipa;

import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import plugin.java.com.plas.crashfilter.analysis.helper.VariableFinder;

import java.util.Set;

public class GlobalVariableAnalysis {
    private Function currentFunction;
    private VariableFinder variableFinder;
    private Set<String> usedGlobalVariables;
    
    public Set<String> getUsedGlobalVariables() {
        return usedGlobalVariables;
    }

    public GlobalVariableAnalysis(Module module, Function function) {
        
        currentFunction = function;
        variableFinder = new VariableFinder(module, currentFunction);    
        usedGlobalVariables = this.variableFinder.getUsedGlobalVariables();

    }
    
    public boolean dontUseGlobalVariable() {
        return variableFinder.getUsedGlobalVariables().size() == 0;
    }
    
    
    public boolean hasSameGlobalVaraible(GlobalVariableAnalysis globalVariableAnalysis) {
        for(String thisVariable : usedGlobalVariables)
        {
            for(String anotherVariable : globalVariableAnalysis.usedGlobalVariables)
            {
                if(thisVariable.equals(anotherVariable))
                {
                    return true;
                }
            }
        }
        return false;        
    }
    
}
