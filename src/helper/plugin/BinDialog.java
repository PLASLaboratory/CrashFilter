package helper.plugin;


import java.awt.BorderLayout;
import java.awt.Checkbox;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextArea;

import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.helpers.MessageBox;
import com.google.security.zynamics.binnavi.API.helpers.ProgressDialog;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.standardplugins.utils.CPanelTwoButtons;

import staticAnalysis.AnalysisStartThread;

public class BinDialog extends JDialog {

	private static final long serialVersionUID = 3510582583037335042L;

	private boolean wasCancelled = true;
	JTextArea filePathField;

	private File f = null;
	private String crashAddr = null;					
	private TextField singleCrashAddrTextfield = new TextField("crashAddr");
	private Checkbox memoryAnalysisCheck = new Checkbox("memoryAnalysis",true);			
	private Checkbox crashSrcAnalysisCheck = new Checkbox("crashSrcAnalysis",true);	
	private Checkbox singleCrashCheck = new Checkbox("singleCrash", true); 	
	private Checkbox CrashCheck = new Checkbox("singleCrash", true); 	
	private Checkbox vsaCheck = new Checkbox("VSA", true); 	
	
	
	int optionalCode = 0;
	// Add, Start Listener
	Module m;
	PluginInterface p;

	public BinDialog(final JFrame parent, final Module module,	PluginInterface m_pluginInterface) {
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
		filePanel.add(new CPanelTwoButtons(new FListener(this), "ADD", "START"),BorderLayout.EAST);
		
		singleCrashAddrTextfield.setText("Single Crash");										//HyeonGu 15.4.21
		filePanel.add(singleCrashAddrTextfield,BorderLayout.AFTER_LAST_LINE);		//HyeonGu 15.4.21
		filePanel.add(singleCrashCheck, BorderLayout.WEST);
		
		
		
		checkerPanel.add(memoryAnalysisCheck, BorderLayout.NORTH);
		checkerPanel.add(crashSrcAnalysisCheck, BorderLayout.CENTER);
		
		
		Panel madeByPanal = new Panel();
		Label madeBytLabel = new Label("                      CNU_PLAS");
		Font font = new Font("πŸ≈¡√º", Font.PLAIN, 10); 
		madeBytLabel.setFont(font);
		madeByPanal.add(madeBytLabel);
		
		
		Panel nameOfProgramPanel = new Panel();
		Label nameOfProgramtLabel = new Label("CrashFilter");
		Font f = new Font("πŸ≈¡√º", Font.PLAIN, 18); 
		nameOfProgramtLabel.setFont(f);
		nameOfProgramPanel.add(nameOfProgramtLabel);
		
		nameOfProgramPanel.add(madeByPanal , BorderLayout.EAST);
        checkerPanel.add(nameOfProgramPanel, BorderLayout.SOUTH);

        
        
        
        
		add(filePanel, BorderLayout.NORTH);
		add(topPanel, BorderLayout.CENTER);
		add(checkerPanel, BorderLayout.SOUTH);
		
		setPreferredSize(new Dimension(800, 250));
		pack();
		
		

	}

	
	private int makeOptionalCode()
	{
		int code = 0;
		
		if(singleCrashCheck.getState()) code |= 1;
		if(memoryAnalysisCheck.getState()) code |= 10;
		if(crashSrcAnalysisCheck.getState()) code |= 100;		
		
		return code;
	}
	public boolean wasCancelled() {
		return wasCancelled;
	}

	public class FListener implements ActionListener {
		final BinDialog jd;

		public FListener(BinDialog jd) {
			super();
			this.jd = jd;
		}		

		@Override
		public void actionPerformed(ActionEvent arg0) {
			// TODO Auto-generated method stub
			if (arg0.getActionCommand().equals("ADD")) {
				JFileChooser jfc = new JFileChooser();
				jfc.setName("Crash File Select");
				jfc.setSize(300, 200);
				jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
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
				AnalysisStartThread analysisStartThread = new AnalysisStartThread(BinDialog.this.p, BinDialog.this.f, BinDialog.this.m ,BinDialog.this.crashAddr, optionalCode);
				ProgressDialog.show(null, "Analysis...", analysisStartThread);
				//System.runFinalization();
				return;
			}
			
		}
	}
}
