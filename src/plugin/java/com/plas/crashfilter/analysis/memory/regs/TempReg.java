package plugin.java.com.plas.crashfilter.analysis.memory.regs;

import plugin.java.com.plas.crashfilter.analysis.memory.IValue;


public class TempReg implements IRegister, IValue{	// Reil Temporary Register
	String tempReg;
	public TempReg(String str) { tempReg = str;}
	
	@Override
	public String getRegName(){ return tempReg;}
//	public int getRegNum() { return num;}
	
	@Override
	public String toString() {return getRegName();}
	public int hashCode() {
		// TODO Auto-generated method stub
		return tempReg.hashCode();
	}
	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		if(obj.getClass() != TempReg.class)
		{
			return false;
		}
		TempReg t = (TempReg)obj;
		return this.tempReg.equals(t.tempReg);
	}

}