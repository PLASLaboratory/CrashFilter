package plugin.java.com.plas.crashfilter.ui;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;

/**
 * Created by User on 2017-08-18.
 */
public class SelectionDialog extends JDialog {
    private JButton loadCrashFilterDialogButton;
    private JButton loadFindPathDialogButton;

    //분석 module, 분석 binary 프로그램에 대한 정보를 가지고 있음음
   private Module analysisModule;

    //BinNavi와 interaction 하기 위해 필요함 많이는 안쓰이지만 반드시 필요함
    private PluginInterface pluginInterface;

    public SelectionDialog(final JFrame parent, PluginInterface pluginInterface,final Module module) {
        super(parent, "CrashFilter 3.0 Development Version");
        this.analysisModule = module;
        this.pluginInterface = pluginInterface;
        loadCrashFilterDialogButton = new JButton("CrashFilter");
        loadFindPathDialogButton = new JButton("FindPath");


        loadCrashFilterDialogButton.addActionListener(e -> {
            BinDialog dlg = new CrashFilterDialog(this.pluginInterface.getMainWindow().getFrame(),
                    module, this.pluginInterface);
            this.dispose();
            dlg.setVisible(true);
        });
        loadFindPathDialogButton.addActionListener(e -> {
            BinDialog dlg = new FindPathDialog(this.pluginInterface.getMainWindow().getFrame(),
                    module, this.pluginInterface);
            this.dispose();
            dlg.setVisible(true);
        });

        final JPanel buttonPanel = new JPanel(new BorderLayout());
        buttonPanel.add(loadCrashFilterDialogButton, BorderLayout.EAST);
        buttonPanel.add(loadFindPathDialogButton, BorderLayout.WEST);
        add(buttonPanel);

    }
}
