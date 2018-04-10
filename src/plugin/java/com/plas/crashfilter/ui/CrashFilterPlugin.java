package plugin.java.com.plas.crashfilter.ui;


//Copyright 2011 Google Inc. All Rights Reserved.
import com.google.common.base.Preconditions;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.ModuleListenerAdapter;
import com.google.security.zynamics.binnavi.API.plugins.IModuleMenuPlugin;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.List;

public final class CrashFilterPlugin implements IModuleMenuPlugin {

	private PluginInterface m_pluginInterface;
	private SelectionDialog dlg;
//test
	private void showDialog(final Module module) {
		Preconditions.checkArgument(module.isLoaded(),
				"Internal Error: Target module is not loaded");
		dlg = new SelectionDialog(m_pluginInterface.getMainWindow().getFrame(), m_pluginInterface, module);

		GuiHelper2.centerChildToParent(m_pluginInterface.getMainWindow()
				.getFrame(), dlg, true);
		dlg.setVisible(true);
		// for every time when a user has not selected a function but a basic
		// block this breaks.
		// As it does throw a null pointer exception.

	}

	public List<JComponent> extendModuleMenu(List<Module> modules) {
		final List<JComponent> menus = new ArrayList<JComponent>();

		if (modules.size() == 1) {
			final Module targetModule = modules.get(0);

			menus.add(new JMenuItem(new AnalysisStart(targetModule)));
		}
		return menus;
	}

	public String getDescription() {
		return "Crash Filter is a tool checking vulnerabilities and exploitable possibility";
	}

	public long getGuid() {
		return 45235244566670943L;
	}

	public String getName() {
		return "CrashFilter Plugin";
	}

	public void init(final PluginInterface pluginInterface) {
		m_pluginInterface = pluginInterface;
	}

	public void unload() {
		// Not used yet
	}

	private class TXTFileFilter implements FilenameFilter {

		public boolean accept(File dir, String name) {
			return name.endsWith(".txt");
		}
	}

	private static class ActionUpdater extends ModuleListenerAdapter {
		private final AbstractAction m_action;

		public ActionUpdater(AbstractAction m_action) {
			super();
			this.m_action = m_action;
		}

		@Override
		public void loadedModule(Module arg0) {
			m_action.setEnabled(true);
		}

	}

	private class AnalysisStart extends AbstractAction {

		private static final long serialVersionUID = 5071188313367826333L;
		private final ActionUpdater m_updater = new ActionUpdater(this);
		Module module;

		public AnalysisStart(final Module module) {
			super("CrashFilter");
			this.module = module;
			setEnabled(module.isLoaded());
			module.addListener(m_updater);
		}

		public void actionPerformed(final ActionEvent e) {

			showDialog(module);
		}
	}
}
