package plugin.java.com.plas.crashfilter.ui;


import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.MessageBox;
import com.google.security.zynamics.binnavi.API.helpers.ProgressDialog;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.standardplugins.utils.CPanelTwoButtons;
import plugin.java.com.plas.crashfilter.analysis.AnalysisStartThread;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public abstract class BinDialog extends JDialog {

	private static final long serialVersionUID = 3510582583037335042L;

	private boolean wasCancelled = true;
	JTextArea filePathField;

	File f = null;
	String crashAddr = null;
	TextField singleCrashAddrTextfield = new TextField("crashAddr");
	Checkbox availableDefinitionCheck = new Checkbox("Available Definition", false);
	Checkbox memoryAnalysisCheck = new Checkbox("memoryAnalysis",true);
	Checkbox crashSrcAnalysisCheck = new Checkbox("crashSrcAnalysis",true);
	Checkbox singleCrashCheck = new Checkbox("singleCrash", true);
	Checkbox interProcedureAnalysisCheck = new Checkbox("interProcedure", true);
	Checkbox callCountCheck = new Checkbox("callCountCheck", true);
	
	int optionalCode = 0;
	// Add, Start Listener
	Module m;
	PluginInterface p;

	public BinDialog(final JFrame parent, final Module module, PluginInterface m_pluginInterface, int jFileMode) {
		super(parent, "CrashFilter", true);
		m = module;
		p = m_pluginInterface;

		setLayout(new BorderLayout());

		final JPanel topPanel = new JPanel(new BorderLayout());

		filePathField = new JTextArea(1, 10);
		filePathField.setEditable(false);

		final JPanel filePanel = new JPanel(new BorderLayout());
		final JPanel checkerPanel = new JPanel(new BorderLayout());
		filePanel.add(filePathField);
		filePanel.add(new CPanelTwoButtons(new FListener(BinDialog.this, jFileMode), "ADD", "START"),BorderLayout.EAST);
		
		singleCrashAddrTextfield.setText("Single Crash");										//HyeonGu 15.4.21
		filePanel.add(singleCrashAddrTextfield,BorderLayout.AFTER_LAST_LINE);		//HyeonGu 15.4.21
		filePanel.add(singleCrashCheck, BorderLayout.WEST);
		
		
		checkerPanel.setLayout(new BoxLayout(checkerPanel, BoxLayout.Y_AXIS));
		checkerPanel.add(availableDefinitionCheck);
		checkerPanel.add(crashSrcAnalysisCheck);
		checkerPanel.add(memoryAnalysisCheck);		
		checkerPanel.add(callCountCheck);
		checkerPanel.add(interProcedureAnalysisCheck);
		
		
		Panel madeByPanal = new Panel();
		Label madeBytLabel = new Label("                      CNU_PLAS");
		Font font = new Font("D2 Coding", Font.PLAIN, 10);
		madeBytLabel.setFont(font);
		madeByPanal.add(madeBytLabel);
		
		
		Panel nameOfProgramPanel = new Panel();
		Label nameOfProgramtLabel = new Label("CrashFilter");
		Font f = new Font("D2 Coding", Font.PLAIN, 18);
		nameOfProgramtLabel.setFont(f);
		nameOfProgramPanel.add(nameOfProgramtLabel);
		
		nameOfProgramPanel.add(madeByPanal , BorderLayout.EAST);
        checkerPanel.add(nameOfProgramPanel);

        
        
        
        
		add(filePanel, BorderLayout.NORTH);
		add(topPanel, BorderLayout.CENTER);
		add(checkerPanel, BorderLayout.SOUTH);
		
		setPreferredSize(new Dimension(800, 250));
		pack();



	}

	
	int makeOptionalCode()
	{
		int code = 0;
		
		if(singleCrashCheck.getState()) code |= 0x1;
		if(memoryAnalysisCheck.getState()) code |= 0x10;
		if(crashSrcAnalysisCheck.getState()) code |= 0x100;
		if(interProcedureAnalysisCheck.getState()) code |= 0x1000;
		if(callCountCheck.getState()) code |= 0x10000;
		if(availableDefinitionCheck.getState()) code |=0x100000;
		return code;
	}
	public boolean wasCancelled() {
		return wasCancelled;
	}

	public class FListener implements ActionListener {
		final BinDialog jd;
		final int jFileMode;
		public FListener(BinDialog jd, int jFileMode) {
			super();
			this.jd = jd;
			this.jFileMode = jFileMode;
		}

		@Override
		public void actionPerformed(ActionEvent arg0) {
			// TODO Auto-generated method stub
			if (arg0.getActionCommand().equals("ADD")) {
				JFileChooser jfc = new JFileChooser();
				jfc.setName("Crash File Select");
				jfc.setSize(300, 200);
				jfc.setFileSelectionMode(jFileMode);
				jfc.showDialog(BinDialog.this, "Analysis");
				f = jfc.getSelectedFile();

				BinDialog.this.filePathField.setText(f.getAbsolutePath());
			}

			else if (arg0.getActionCommand().equals("START")) {
				optionalCode = makeOptionalCode();
				crashAddr = singleCrashAddrTextfield.getText();
				if(!singleCrashCheck.getState())
				{
					if (f == null) {
						MessageBox.showInformation(BinDialog.this, "Error: No File");
						return;
					}
				}

				jd.dispose();
				analysisStart();

				//System.runFinalization()
			}
		}
	}

	protected abstract void analysisStart();

}
