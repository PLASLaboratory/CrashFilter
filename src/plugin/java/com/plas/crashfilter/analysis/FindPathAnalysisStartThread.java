package plugin.java.com.plas.crashfilter.analysis;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.IProgressThread;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import plugin.java.com.plas.crashfilter.analysis.ipa.InterProcedureMode;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;

import java.io.File;

/**
 * Created by User on 2017-08-28.
 */
public class FindPathAnalysisStartThread implements IProgressThread {
    private BackwardAnalysisRunner backwardAnalysisRunner;

    public FindPathAnalysisStartThread(PluginInterface m_plugin, File crachFolder, Module module, String crashAddr, int optionCode) {
        super();
        backwardAnalysisRunner = new BackwardAnalysisRunner(m_plugin, crachFolder,module, crashAddr, optionCode);
    }

    public void run() throws MLocException, InternalTranslationException {
        backwardAnalysisRunner.run();
    }

    public boolean close() {
        // TODO Auto-generated method stub
        return false;
    }
}
