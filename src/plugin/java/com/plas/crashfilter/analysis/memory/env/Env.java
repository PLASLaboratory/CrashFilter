package plugin.java.com.plas.crashfilter.analysis.memory.env;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import plugin.java.com.plas.crashfilter.analysis.helper.MFactoryHelper;
import plugin.java.com.plas.crashfilter.analysis.helper.MemoryCounter;
import plugin.java.com.plas.crashfilter.analysis.memory.IALoc;
import plugin.java.com.plas.crashfilter.analysis.memory.IValue;
import plugin.java.com.plas.crashfilter.analysis.memory.IValueGrade;
import plugin.java.com.plas.crashfilter.analysis.memory.Val;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.StructuredMLoc;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Bottom;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Top;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.ActualReg;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.TempReg;

import java.util.*;

public class Env extends AbstractMap<IALoc, Set<IValue>> implements Map<IALoc, Set<IValue>> {
	
	public Env(){
		tableEntries = new HashSet<java.util.Map.Entry<IALoc, Set<IValue>>>();
	}
	
	Set<java.util.Map.Entry<IALoc, Set<IValue>>> tableEntries;
	
	public Set<IValue> put(IALoc s, Set<IValue> v){
		tableEntries.add(new AbstractMap.SimpleEntry<IALoc, Set<IValue>>(s, v));
		return v;
	}
	@Override
	public Set<java.util.Map.Entry<IALoc, Set<IValue>>> entrySet() {
		// TODO Auto-generated method stub
		return tableEntries;
	}
	public void putElements(IALoc key, Set<IValue> values)
	{
		if(this.containsKey(key))
		{
			this.remove(key);
		}
		this.put(key, values);
	}
	public Set<IValue> combineIValueSet(Set<IValue> vs1, Set<IValue> vs2 )
	{
		Set<IValue> result = new HashSet<IValue>();
		for(IValue v1 : vs1)
		{
			result.add(v1);
		}
		for(IValue v2:vs2)
		{
			if(result.contains(v2))
			{
				
			}
			else
			{
				result.add(v2);
			}
		}
		
		
		return result;
	}
	public Env copy()
	{
		Iterator<Entry<IALoc, Set<IValue>>> iter = tableEntries.iterator();
		Env result = new Env();
		while(iter.hasNext())
		{
			Entry<IALoc, Set<IValue>> ent = iter.next();
			IALoc key = ent.getKey();
			if(key instanceof ActualReg)
			{
				//nothing have to do.
			}
			else if(key instanceof TempReg)
			{
				key= new TempReg(((TempReg)key).getRegName());
			}
			Set<IValue> saveVT ;
			Set<IValue> vT = ent.getValue();
			
			
			saveVT = copyIValueSet(vT);
			
			result.putElements(key, saveVT);
		}
		return result;
	}
	private Set<IValue> copyIValueSet(Set<IValue> vT)
	{
		if(vT==null)
		{
			return null;
		}
		Set<IValue> saveVT = new HashSet<IValue>();
		for(IValue value : vT)
		{
			IValue copyValue=null;
			if(value instanceof Val)
			{
				Val val = new Val(((Val)value).getValue());
				copyValue = val;
				
			}
			else if(value instanceof StructuredMLoc)
			{
				StructuredMLoc val = ((StructuredMLoc) value).copy();
				copyValue = val;
			}
			else
			{
				copyValue = value;	//top or bottom..
			}
			
			saveVT.add(copyValue);
		}
		return saveVT;
	}

	
	@Override
	public boolean equals(Object o) {
		// TODO Auto-generated method stub
		if(  !( o instanceof Env ))
		{
			return false;
		}
		
		Env env2 = (Env)o;
		
		Set<IALoc> envKeys1 = this.keySet();
		Set<IALoc> envKeys2 = env2.keySet();
		
		if(! (envKeys1.containsAll(envKeys2) && envKeys2.containsAll(envKeys1)))
		{
			return false;
		}
		
		for(IALoc key : envKeys1)
		{
			Set<IValue> values1 = this.get(key);
			Set<IValue> values2 = env2.get(key);
			if(!(values1.equals(values2)))
			{
				return false;
			}
		}
		
		return true;
		
	}
	
	public Env combine(Env env) {
		// TODO Auto-generated method stub
		Env combinedEnv = null; 
		
		Env env1 = this.copy();
		Env env2 = env.copy();
		
		Set<IALoc> keys1 = env1.keySet();
		Set<IALoc> keys2 = env2.keySet();
		
		
		for(IALoc key2 : keys2)
		{
			if(env1.containsKey(key2))
			{
				Set<IValue> value  = combineIValueSet(env1.get(key2), env2.get(key2));
				env1.remove(key2);
				env1.putElements(key2, value);
			}
			else
			{
				env1.putElements(key2, env2.get(key2));
			}
		}
		combinedEnv = env1;
		
		return combinedEnv;
		
	}
	public boolean lessthan(Env env) {
		//return !this.equals(env);
		if(this == env || this.equals(env))
		{
			return false;
		}
		
		Set<IALoc> loc1key = this.keySet();
		Set<IALoc> loc2key = env.keySet();
		for(IALoc loc1 : loc1key)
		{
			if(env.containsKey(loc1))
			{
				IValueGrade r1g = IValueGrade.getValueSetSymbol(this.get(loc1));
				IValueGrade r2g = IValueGrade.getValueSetSymbol(env.get(loc1));
				if((r1g.lessThan(r2g)))
				{
					return true;
				}
			}
			else
			{
				return false;
			}
		}
		//TODO
		return true;
	}
	
	public void printEnv()
	{
		MemoryCounter memoryCounter = MemoryCounter.getMemoryCounter();
		
		for(IALoc memorylocation : this.keySet())
		{
			if(memorylocation instanceof StructuredMLoc)
			{
				StructuredMLoc memoryStruct = (StructuredMLoc) memorylocation;
				if(memoryStruct.getReg2().getRegName().equals("stack"))
				{
					memoryCounter.countStack();
				}
				else if(memoryStruct.getReg2().getRegName().equals("heap"))
				{
					memoryCounter.countHeap();
				}
			}
			LogConsole.log("Key : "+memorylocation+"\n");
			for(IValue value : this.get(memorylocation))
			{
				LogConsole.log("\tValue : "+value+"\n" );
			}
			
		}
	}
	

	public void deleteTempReg()
	{
		

		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IALoc> keyset = keySet();
		for(IALoc key : keyset)
		{
			if(key instanceof StructuredMLoc)
			{
				//LogConsole.log(key+"\n");
				if(((StructuredMLoc)key).getReg2() instanceof TempReg)
				{
					//LogConsole.log("tempreg : "+((StructuredMLoc)key).getReg2()+"\n");
					toBeRemoved.add(key);
				}
			}
			
		}
		for ( IALoc key: toBeRemoved ) {
			remove(key);
		}
		

	}
	public IValue checkStackOrHEapMemory( String string) throws MLocException
	{
		boolean stack=false ;
		boolean heap=false;
		
		IRegister reg = MFactoryHelper.newIRegister(string);
		StructuredMLoc key = new StructuredMLoc.StructuredMLocBuilder()
								.reg2(reg)
								.c2(new Val(0)).build();
		if(reg instanceof ActualReg)
		{
			
			Set<IValue> vals = this.get(key);
			if(vals==null)
			{
				return null;
			}
			for(IValue v: vals)
			{
				if(v instanceof Symbol_Bottom){}
				else if(v instanceof Symbol_Top)
				{
					return Symbol_Top.getSymbolTop();
				}
				else if(v instanceof StructuredMLoc)
				{
					StructuredMLoc st = (StructuredMLoc)v;
					if(st.getReg2().equals(new ActualReg("stack")))
					{
						stack = true;
					}
					else if(st.getReg2().equals(new ActualReg("heap")))
					{
						heap = true;
					}
				}
				else if(v instanceof IRegister)
				{
					//
					IRegister r = (IRegister)v;
					if(r.equals(new ActualReg("heap")))
					{
						heap =true;
					}
					else if(r.equals(new ActualReg("stack")))
					{
						stack =true;
					}
				}
				
			}
		}
		else
		{
			return null;
		}
		if(stack == true && heap ==false)
		{
			return new ActualReg("stack");
		}
		else if(stack == false && heap ==true)
		{
			return new ActualReg("stack");
		}
		else if (stack == false && heap == false)
		{
			return null;
		}
		else if (stack == false && heap == false)
		{
			return Symbol_Top.getSymbolTop();
		}
		
		return null;
		
	}
	public void deleteNullNBottom() {
		Set<IALoc> toBeRemoved = new HashSet<IALoc>();
		for(IALoc key : keySet())
		{
			Set<IValue> valueSet = get(key);
			if(valueSet.size() == 1 && valueSet.contains(Symbol_Bottom.getSymbolBottom()))
			{
				toBeRemoved.add(key);
			}
			if(valueSet.size() ==0)
			{
				toBeRemoved.add(key);
			}
		}
		
		for(IALoc key : toBeRemoved)
		{
			this.remove(key);
		}	
		
	}
	
	
	
}
