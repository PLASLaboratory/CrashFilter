package plugin.java.com.plas.crashfilter.analysis.memory;

import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Bottom;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Top;

import java.util.Set;

public enum IValueGrade {
	Top(3), Normal(2), Bottom(1);
	
	public int gradeValue;
	
	IValueGrade(int a)
	{
		this.gradeValue = a;
	}
	
	public boolean lessThan(IValueGrade vg)
	{
		return this.gradeValue<vg.gradeValue;
	}
	
	public static IValueGrade getValueSetSymbol(Set<IValue> valueSet)
	{
		IValueGrade vg = IValueGrade.Bottom;
		for(IValue v : valueSet)
		{
			if(v instanceof Symbol_Top)
			{
				vg = IValueGrade.Top;
				return vg;
			}
			else if(v instanceof Symbol_Bottom)
			{
				// not changed
			}
			else // IValue ( Val, IRegister, Struct....)
			{
				if(vg == IValueGrade.Bottom)
				{
					vg = IValueGrade.Normal;
				}
			}
		}		
		
		return vg;
	}
	
	public static IValueGrade getValueSetSymbolForEnv(Set<IALoc> valueSet)
	{
		IValueGrade vg = IValueGrade.Bottom;
		for(IALoc v : valueSet)
		{
			if(v instanceof Symbol_Top)
			{
				vg = IValueGrade.Top;
				return vg;
			}
			else if(v instanceof Symbol_Bottom)
			{
				// not changed
			}
			else // IValue ( Val, IRegister, Struct....)
			{
				if(vg == IValueGrade.Bottom)
				{
					vg = IValueGrade.Normal;
				}
			}
		}		
		
		return vg;
	}
	
	
}