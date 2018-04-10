package plugin.java.com.plas.crashfilter.ui;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.ProgressDialog;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import plugin.java.com.plas.crashfilter.analysis.FindPathAnalysisStartThread;

import javax.swing.*;

/**
 * Created by User on 2017-08-18.
 */
public class FindPathDialog extends BinDialog {
    public FindPathDialog(JFrame parent, Module module, PluginInterface m_pluginInterface) {
        super(parent, module, m_pluginInterface, JFileChooser.FILES_ONLY);
    }

    @Override
    protected void analysisStart() {

        FindPathAnalysisStartThread findPathAnalysisStartThread = new FindPathAnalysisStartThread(this.p, this.f, this.m ,this.crashAddr, optionalCode);
        ProgressDialog.show(null, "Find Path Analysis...", findPathAnalysisStartThread);
    }
}
