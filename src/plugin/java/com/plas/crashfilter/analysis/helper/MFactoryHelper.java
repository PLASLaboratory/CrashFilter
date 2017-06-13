package plugin.java.com.plas.crashfilter.analysis.helper;

import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.StructuredMLoc;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.ActualReg;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.TempReg;

public class MFactoryHelper {
	public static StructuredMLoc newStructuredMLocFromOp()
	{
		return null;
	}
	
	public static IRegister newIRegister(ReilOperand op)
	{
		String str = op.getValue();
		return isActualRegister(str)? new ActualReg(str) : new TempReg(str);
	}
	public static IRegister newIRegister(String str)
	{
		return isActualRegister(str)? new ActualReg(str) : new TempReg(str);
	}
	private static boolean isActualRegister(String reg)
	{
		return !(reg.charAt(0)=='t' || reg.charAt(0)=='k');
	}

}
