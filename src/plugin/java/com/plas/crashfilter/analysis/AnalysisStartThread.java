package plugin.java.com.plas.crashfilter.analysis;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.IProgressThread;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import plugin.java.com.plas.crashfilter.analysis.ipa.InterProcedureMode;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;

import java.io.File;

public class AnalysisStartThread implements IProgressThread {
    
    private AnalysisRunner analysisRunner;    
    
    public AnalysisStartThread(PluginInterface m_plugin, File crachFolder, Module module, String crashAddr, int optionCode) {        
        super();        
        analysisRunner = new AnalysisRunner( m_plugin,  crachFolder,  module,  crashAddr,  optionCode);
        
    }

    public void run() throws MLocException, InternalTranslationException {
        analysisRunner.runAnalysis(InterProcedureMode.NORMAL);
    }

    public boolean close() {
        // TODO Auto-generated method stub
        return false;
    }

}
