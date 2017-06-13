package plugin.java.com.plas.crashfilter.analysis.ipa;

import com.google.security.zynamics.binnavi.API.disassembly.Callgraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.FunctionEdge;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import plugin.java.com.plas.crashfilter.analysis.helper.VariableFinder;

import java.util.ArrayList;
import java.util.List;

public class FunctionCallAnalysis {

    private Function currentFunction;
    private VariableFinder variableFinder;
    private Module module;
    private List<Function> callees = new ArrayList<Function>();

    public List<Function> getCallees() {
        return callees;
    }

    public FunctionCallAnalysis(Module module, Function function) {
        currentFunction = function;
        variableFinder = new VariableFinder(module, currentFunction);
        this.module = module;

        callees = getCallees(currentFunction);
    }

    public List<Function> getCallees(Function function) {

        Callgraph callgraph = module.getCallgraph();

        List<Function> callees = new ArrayList<Function>();

        for (FunctionEdge functionEdge : callgraph.getEdges()) {
            if (functionEdge.getSource().getFunction().getAddress().toLong() == function.getAddress().toLong()) {
                callees.add(functionEdge.getTarget().getFunction());
            }
        }
        return null;
    }


    public boolean dontHaveArgument() {
        return variableFinder.getUsedArguments().size() == 0;
    }


}
