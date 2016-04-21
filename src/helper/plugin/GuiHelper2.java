package helper.plugin;


import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;


public class GuiHelper2 {
	  public static final void centerChildToParent(final Component parent, final Component child,
		      final boolean bStayOnScreen) {
		    int x = (parent.getX() + (parent.getWidth() / 2)) - (child.getWidth() / 2);
		    int y = (parent.getY() + (parent.getHeight() / 2)) - (child.getHeight() / 2);
		    if (bStayOnScreen) {
		      final Toolkit tk = Toolkit.getDefaultToolkit();
		      final Dimension ss = new Dimension(tk.getScreenSize());
		      if ((x + child.getWidth()) > ss.getWidth()) {
		        x = (int) (ss.getWidth() - child.getWidth());
		      }
		      if ((y + child.getHeight()) > ss.getHeight()) {
		        y = (int) (ss.getHeight() - child.getHeight());
		      }
		      if (x < 0) {
		        x = 0;
		      }
		      if (y < 0) {
		        y = 0;
		      }
		    }
		    child.setLocation(x, y);
		  }

		  public static String getMonospaceFont() {
		    final GraphicsEnvironment env = GraphicsEnvironment.getLocalGraphicsEnvironment();
		    final Font[] allfonts = env.getAllFonts();

		    for (final Font font : allfonts) {
		      if (font.getName().equals("Courier New")) {
		        return "Courier New";
		      }
		    }

		    return Font.MONOSPACED;
		  }
}
