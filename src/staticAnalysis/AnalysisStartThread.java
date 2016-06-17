package staticAnalysis;

import java.io.File;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.IProgressThread;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;

import crashfilter.va.memlocations.MLocException;
import helper.InterProcedureMode;

public class AnalysisStartThread implements IProgressThread {
    
    private AnalysisRunner analysisRunner;    
    
    public AnalysisStartThread(PluginInterface m_plugin, File crachFolder, Module module, String crashAddr, int optionCode) {        
        super();        
        analysisRunner = new AnalysisRunner( m_plugin,  crachFolder,  module,  crashAddr,  optionCode, 0);
        
    }

    @Override
    public void run() throws MLocException {
        analysisRunner.runAnalysis(InterProcedureMode.NORMAL);
    }

    @Override
    public boolean close() {
        // TODO Auto-generated method stub
        return false;
    }

}
