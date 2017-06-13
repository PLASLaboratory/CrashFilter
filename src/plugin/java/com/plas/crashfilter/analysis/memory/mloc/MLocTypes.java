package plugin.java.com.plas.crashfilter.analysis.memory.mloc;

import plugin.java.com.plas.crashfilter.analysis.memory.Val;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;

public enum MLocTypes {
	R2nC2,				// ebp + c2 
	StarR1nC1_C2, 		// *(r1+c1) + c2    	or *(esi+c1) + c2
	StarR1nC1_R2nC2,	// *(r1+c1) + ebp+c2    or *(ebp+c1) + ebp+c2   
	TempLocK, 			// k_i
	ValConst,  			// 0x201000
	Unnwown	;			//
	public static MLocTypes getMLocType(IRegister r1, Val c1, IRegister r2, Val c2) throws MLocException{
		if (r1== null && c1 == null && r2 != null && c2!=null )
			return R2nC2;
		
		if (r1!= null && c1 != null && r2 == null && c2!=null )
			return StarR1nC1_C2;
		
		if (r1!= null && c1 != null && r2 != null && c2!=null )
			return StarR1nC1_R2nC2;
		
		if (r1==null && c1 == null && r2 == null && c2==null )
			return TempLocK;
		
		throw new MLocException();
	}
}