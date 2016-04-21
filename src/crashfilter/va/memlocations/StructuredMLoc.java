package crashfilter.va.memlocations;
import helper.MFactoryHelper;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;

import crashfilter.va.Val;
import crashfilter.va.MLocAnalysis.IValue;
import crashfilter.va.regs.ActualReg;
import crashfilter.va.regs.IRegister;

public class StructuredMLoc implements IMLoc, IValue {
	// *(reg1 + c1) + reg2 + c2
	// reg2:  to check if reg2 happens to be esi
	
		
		IRegister reg1;		Val c1;
		IRegister reg2;		Val c2;
		MLocTypes type;
	
	private StructuredMLoc(StructuredMLocBuilder builder) throws MLocException {
		this.reg1 = builder.reg1; 	this.c1 = builder.c1;			
		this.reg2 = builder.reg2; 	this.c2 = builder.c2;
		this.type = MLocTypes.getMLocType(this.reg1, this.c1, this.reg2, this.c2);	
	}
	
	public static StructuredMLoc newStructuredMLoc(ReilOperand op) throws MLocException
	{
		IRegister register = MFactoryHelper.newIRegister(op);
		
		StructuredMLoc result= new StructuredMLoc.StructuredMLocBuilder()
								.reg2(register)
								.c2(new Val(0)).build();
		
		return result;
	}
	
	
	public static class StructuredMLocBuilder{
		IRegister reg1 	= null;		Val c1 	= null;
		IRegister reg2 	= null;		Val c2 	= null;
		
		public StructuredMLocBuilder(){}
		
		public StructuredMLocBuilder reg1(IRegister r1) 	throws MLocException	{
			if (this.reg1 != null)
				throw new MLocException();
			this.reg1 = r1; 
			return this;
		}
		
		public StructuredMLocBuilder c1(Val c1) 			throws MLocException	{
			if (this.c1 != null)
				throw new MLocException();
			this.c1 = c1; 
			return this;
		}
		
		
		public StructuredMLocBuilder reg2(IRegister r2) 	throws MLocException	{
			if (this.reg2 != null)
				throw new MLocException();
			reg2 = r2; 
			return this;
		}
		
		public StructuredMLocBuilder c2(Val c2) 			throws MLocException	{
			if (this.c2 != null)
				throw new MLocException();
			this.c2 = c2; 
			return this;
		}
		
		public StructuredMLoc build() throws MLocException{// IMLoc -> StructuredMLoc ?? 
			return new StructuredMLoc(this);
		}
	}

	@Override
	public MLocTypes getMLocType() {
		return this.type;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "*("+reg1+" + "+c1+")+ "+reg2+" + "+c2+" ";
	}
	@Override
	public int hashCode() {
		// TODO Auto-generated method stub			
		return this.toString().hashCode();
	}
	@Override
	public boolean equals(Object obj) {
		boolean result ;
		if(!(obj instanceof StructuredMLoc)){return false;}
		
		StructuredMLoc o = (StructuredMLoc) obj;
		
		String str1 = this.toString();
		String str2 = o.toString();
		
		result = str1.equals(str2);
		
		return result;
	}

	
	public StructuredMLoc copy()
	{
		StructuredMLoc result =null;
		
		try {
			Val valC1 = null;
			Val valC2 = null;
			if(c1 != null)
			{
				 valC1 = new Val(this.c1.getValue());
			}
			if(c2 != null)
			{
				 valC2 = new Val(this.c2.getValue());
			}
			
			result	= new StructuredMLoc.StructuredMLocBuilder()
								.reg1(this.reg1).c1(valC1)
								.reg2(this.reg2).c2(valC2).build();
		} catch (MLocException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if(result == null)
		{
			LogConsole.log(" StructuredMLoc copy() : copy fail\n");
		}
		return result;
		
	}
	
	//getter & setter
	public IRegister getReg1() {
		return reg1;
	}

	public void setReg1(IRegister reg1) {
		this.reg1 = reg1;
	}

	public Val getC1() {
		return c1;
	}

	public void setC1(Val c1) {
		this.c1 = c1;
	}

	public IRegister getReg2() {
		return reg2;
	}

	public void setReg2(IRegister reg2) {
		this.reg2 = reg2;
	}

	public Val getC2() {
		return c2;
	}

	public void setC2(Val c2) {
		this.c2 = c2;
	}
	
	
}
