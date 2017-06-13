package plugin.java.com.plas.crashfilter.analysis.memory.RTable;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.*;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import plugin.java.com.plas.crashfilter.analysis.helper.AddressTransferHelper;
import plugin.java.com.plas.crashfilter.analysis.helper.MFactoryHelper;
import plugin.java.com.plas.crashfilter.analysis.memory.IALoc;
import plugin.java.com.plas.crashfilter.analysis.memory.IValue;
import plugin.java.com.plas.crashfilter.analysis.memory.Val;
import plugin.java.com.plas.crashfilter.analysis.memory.env.EdgeMapper;
import plugin.java.com.plas.crashfilter.analysis.memory.env.Env;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.StructuredMLoc;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Bottom;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.Symbol_Top;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.ActualReg;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.TempReg;
import plugin.java.com.plas.crashfilter.util.ReilInstIndex;
import plugin.java.com.plas.crashfilter.util.ReilInstructionResolve;

import java.util.*;

public class IRSetManager { // singleton
	
	RTable rTable = null;
	
	private ILatticeGraph<InstructionGraphNode> instGraph ;
	private ReilGraph reilGraph;	
	private EdgeMapper edgeMapper;
	private Env env;
	private Function func;
	private boolean callStackFlag = false; 
	private final static Map<String, ReilInstIndex> instStringToInstValue = new HashMap<String, ReilInstIndex>();
	static {
		instStringToInstValue.put("add", ReilInstIndex.ADD);
		instStringToInstValue.put("and", ReilInstIndex.AND);
		instStringToInstValue.put("bisz", ReilInstIndex.BISZ);
		instStringToInstValue.put("bsh", ReilInstIndex.BSH);
		instStringToInstValue.put("div", ReilInstIndex.DIV);
		instStringToInstValue.put("jcc", ReilInstIndex.JCC);
		instStringToInstValue.put("ldm", ReilInstIndex.LDM);
		instStringToInstValue.put("mod", ReilInstIndex.MOD);
		instStringToInstValue.put("mul", ReilInstIndex.MUL);
		instStringToInstValue.put("nop", ReilInstIndex.NOP);
		instStringToInstValue.put("or", ReilInstIndex.OR);
		instStringToInstValue.put("stm", ReilInstIndex.STM);
		instStringToInstValue.put("str", ReilInstIndex.STR);
		instStringToInstValue.put("sub", ReilInstIndex.SUB);
		instStringToInstValue.put("undef", ReilInstIndex.UNDEF);
		instStringToInstValue.put("unkn", ReilInstIndex.UNKNOWN);
		instStringToInstValue.put("xor", ReilInstIndex.XOR);
	}
	
	public void setEnv(Env env)
	{
		this.env = env;
	}
	private IRSetManager(RTable rt)
	{
		if(rt == null)
		{
			rTable = new RTable();
		}
		else
		{
			rTable = rt;
		}
		env = null;
	}
	
	private IRSetManager()
	{
		rTable = new RTable();
		initFirst();
	}
	
	public void setFunction(Function curFunc)
	{
		this.func = curFunc;
	}
	public RTable initFirst() {
		IRegister init_esp = null ;
		StructuredMLoc init_stack = null ;
		IRegister init_ebp = null ;
		StructuredMLoc init_oldebp = null;
		IRegister init_heap = null ;
		
		Set<IValue> value = new HashSet<IValue>();
		
		try {
			//init esp-> stack0
			init_esp =  new ActualReg("esp");			
			init_stack =  new StructuredMLoc.StructuredMLocBuilder()
						.reg2(new ActualReg("stack"))
						.c2(new Val(4)).build();

			value.add(init_stack);
			putElements(init_esp, value );
			
			value = new HashSet<IValue>();
			//init ebp-> old ebp			
			init_ebp =  new ActualReg("ebp");
			init_oldebp =  new StructuredMLoc.StructuredMLocBuilder()
									.reg2(new ActualReg("oldebp"))
									.c2(new Val(0)).build();
			value.add(init_oldebp);
			putElements(init_ebp, value );
			
			
			
			//for arm	
			ActualReg init_SP = new ActualReg("SP");			
			StructuredMLoc init_stack_0 = new StructuredMLoc.StructuredMLocBuilder()
					.reg2(new ActualReg("stack"))
					.c2(new Val(0)).build();
			value.add(init_stack_0);
			putElements(init_SP, value );
			
			ActualReg init_LR = new ActualReg("LR");			
			StructuredMLoc retAddr = new StructuredMLoc.StructuredMLocBuilder()
					.reg2(new ActualReg("retAddr"))
					.c2(new Val(0)).build();
			value.add(retAddr);
			putElements(init_LR, value );
			
			
			//for heap
			value = new HashSet<IValue>();
			init_heap = new ActualReg("heap");
			putElements(init_heap, value);
			
		} catch (MLocException e) {
			e.printStackTrace();
		}
		return rTable;		
	}
	public RTable initEax2Heap() throws MLocException {
		
		IRegister eax = new ActualReg("eax");
		Set<IValue> vs = new HashSet<IValue>();
		vs.add(new ActualReg("heap"));
		
		putElements(eax, vs);
		
		return rTable;
	}

	public RTable init() throws MLocException {
		Set<IValue> value = new HashSet<IValue>();
		
		//init esp-> stack0
		initRegBottom("eax", new HashSet<IValue>());
		initRegBottom("ebx", new HashSet<IValue>());
		initRegBottom("ecx", new HashSet<IValue>());
		initRegBottom("edx", new HashSet<IValue>());
		initRegBottom("edi", new HashSet<IValue>());
		initRegBottom("esi", new HashSet<IValue>());
		initRegBottom("ZF", new HashSet<IValue>());
		initRegBottom("OF", new HashSet<IValue>());
		initRegBottom("CF", new HashSet<IValue>());
		initRegBottom("SF", new HashSet<IValue>());
		
		
		//for  temp reg
		for(int i=0; i<20; i++)
		{
			initRegBottom("t"+i, value);
		}
		
		//for arm
		initRegBottom("C", new HashSet<IValue>());
		initRegBottom("N", new HashSet<IValue>());
		initRegBottom("V", new HashSet<IValue>());
		for(int i=0; i<16; i++)
		{
			initRegBottom("R"+i, new HashSet<IValue>());
		}
		return rTable;		
	}
	
	void initRegBottom(String str, Set<IValue> value)
	{
		IRegister init_reg = null ;
		Symbol_Bottom init_value = null ;
		
		init_reg =  MFactoryHelper.newIRegister(str);			
		init_value =  Symbol_Bottom.getSymbolBottom();

		value.add(init_value);
		putElements(init_reg, value );
	}
	
	static IRSetManager IRMGR = null;
	public static IRSetManager getIRSetManager(){
		if (IRMGR != null)
			return IRMGR;
		else
			return new IRSetManager();
	}
	
	
	public void setRTable(RTable rt)
	{
		this.rTable = rt;
	}
	
	public RTable getRTable()
	{
		return this.rTable;
	}
	public void setGraph(ReilFunction curReilFunc)
	{
		instGraph= InstructionGraph.create(curReilFunc.getGraph());	
		reilGraph = curReilFunc.getGraph();		
	}
	
	public void oneReilInst( ReilInstruction inst) throws MLocException{

		//rTable = rt;
		ReilOperand op1 = inst.getFirstOperand();
		ReilOperand op2 = inst.getSecondOperand();		
		ReilOperand op3 = inst.getThirdOperand();
		
		switch (instStringToInstValue.get(inst.getMnemonic())) {
			case ADD: // addition
				addOperation(op1,op2,op3);
				break;
			case AND: // binary and
				andOperation(op1,op2,op3);
				break;
			case BISZ: // boolean is zero
				biszOperation(op1,op2,op3);
				break;
			case BSH: // binary shift
				bshOperation(op1,op2,op3);
				break;
			case DIV: // unsigned division
				divOperation(op1,op2,op3);
				break;
			case JCC:
				break;
			case LDM:
				ldmOperation(op1,op2,op3);
				break;
			case MOD:
				modOperation(op1, op2, op3);
				break;
			case MUL: // unsigned multiplication
				mulOperation(op1,op2,op3);
				break;
			case NOP: // no operation
				break;
			case OR: // bitwise Or
				orOperation(op1,op2,op3);
				break;
			case STM: // store to memory
				stmOperation(op1,op2,op3);
				break;
			case STR: // store to register
				strOperation(op1,op2,op3);
				break;
			case SUB: // subtract
				subOperation(op1,op2,op3);
				break;
			case UNDEF:
			case UNKNOWN: // unknown operation ( placeholder instruction )
				break;
			case XOR:
				xorOperation(op1,op2,op3);
				break;
			default: // Exception
				break;
		}
		
		
	}

	
	public void runValueAnalysis()
	{
		LogConsole.log("---------Start-----------\n");
		for (InstructionGraphNode inst : instGraph.getNodes())
		{			
			if(inst.getInstruction().getAddress().toLong()% 0x100 == 0)
			{
					clearCallStack(inst);
			}
			
			try {
				oneReilInst( inst.getInstruction());
			} catch (MLocException e) {
				e.printStackTrace();
			}
			
			//rTable.printRTable();
			//env.printEnv();
			LogConsole.log("--------------------\n");
		}
		
		deleteTempRegster(rTable);
		
		
		
		LogConsole.log("-----------end---------\n");
	}
	
	private void deleteTempRegster(RTable rt)
	{
		
		LogConsole.log("-----------------------delete temp start\n");
		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IRegister> keyset = rt.keySet();
		for(IRegister key : keyset)
		{
			if(key instanceof TempReg)
			{				
				toBeRemoved.add(key);
			}			
		}
		for ( IALoc key: toBeRemoved ) {
			rt.remove(key);
		}
		
		LogConsole.log("-----------------------delete temp end\n");
	}
	
	
	private void biszOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		int op1v=0; 
		Set<IValue> value = new HashSet<IValue>();
		
		
		if(op1.getType() == OperandType.REGISTER)
		{
			IRegister op1reg = MFactoryHelper.newIRegister(op1);
			Set<IValue> op1locs = opInit(op1);
			for(IValue temp : op1locs)
			{
				if (temp instanceof Val)
				{
					op1v = ((Val)temp).getValue();
					value.add(new Val( op1v == 0? 1:0 ));
				}
				else
				{
					value.add(Symbol_Top.getSymbolTop());
				}
			}
		}
		else if(op1.getType() == OperandType.INTEGER_LITERAL)
		{
			op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			value.add(new Val( op1v == 0? 1:0 ));
		}
		else
		{
			//err
		}

		
		putElements(op3reg, value);

		
	}
	private void bshOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		//If the second operand is positive, the shift is a left-shift. 
		//If the second operand is negative, the shift is a right-shift. 
		if(op2.getValue().equals("0"))
		{			
			strOperation(op1,op2,op3);
			return;
		}
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();;
		
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					Val op1Val = (Val)op1loc;
					Val op2Val = (Val)op1loc;
					int op1v = op1Val.getValue();
					int op2v = op2Val.getValue();
					value.add(bshCalc( op1v,  op2v));		
				}
				else 
				{
					value.add( Symbol_Top.getSymbolTop()) ;
				}
			}
		}
		putElements(op3reg, value);
		
	}
	
	private Val bshCalc(int op1v, int op2v)
	{
		if(op2v<0)
		{
			op2v *= -1;
			return new Val(op1v >> op2v);
		}
		else
		{
			return new Val(op1v << op2v);
		}
	}
	
	private void strOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		Set<IValue> op1locs=opInit(op1);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		putElements(op3reg, op1locs);
	}
	private void stmOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		Set<IValue> op1locs = opInit(op1);
		Set<IValue> op3locs = opInit(op3);
		Set<IValue> value = new HashSet<IValue>();

		for(IValue val : op3locs)
		{
			if(val instanceof IRegister)
			{
				//MLoc -HG
				IRegister key = (IRegister) val;
				this.putElements(key, op1locs);
			}
			if(val instanceof StructuredMLoc)
			{
				if(this.env == null)
				{
					LogConsole.log("err : IRSetmanager.java - stmOperation() : env is null !! \n");
				}
				StructuredMLoc key = (StructuredMLoc) val;
				this.env.putElements(key, op1locs);
			}
		}
	}
	
	private void ldmOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		Set<IValue> op1loc=opInit(op1);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> loadedDatas = new HashSet<IValue>();
		
		for(IValue val : op1loc)
		{
			Set<IValue> regVal = new HashSet<IValue>();
			if(val instanceof IRegister)
			{
				IRegister reg = (IRegister)val;
				Set<IValue> data = this.getElements(reg);
				loadedDatas.addAll(data);
			}
			else if (val instanceof StructuredMLoc)
			{
				StructuredMLoc memoryLocation = (StructuredMLoc) val;
				if(env.containsKey(memoryLocation))
				{
					Set<IValue> data = env.get(memoryLocation);
					if(data ==null)
					{
						data.add(Symbol_Bottom.getSymbolBottom());
					}
					loadedDatas.addAll(data);
				}
				else
				{
					
				}
			}
			
		}
		this.putElements(op3reg, loadedDatas);
	}
	
	private void andOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		if(op1.getValue().equals("4294967295"))
		{			
			strOperation(op2,op1,op3);
			return;
		}
		if(op1.getValue().equals("4294967280"))
		{			
			strOperation(op2,op1,op3);
			return;
		}
		
		if(op2.getValue().equals("4294967295"))
		{			
			strOperation(op1,op2,op3);
			return;
		}
		if(op2.getValue().equals("4294967280"))
		{			
			strOperation(op1,op2,op3);
			return;
		}
/*		todo
		if(op2.getValue().equals("4294967296"))
		{			
			strOperation(op1,op2,op3);
			return;
		}
		if(op2.getValue().equals("4294967296"))
		{			
			strOperation(op1,op2,op3);
			return;
		}
		*/
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					Val op1Val = (Val)op1loc;
					Val op2Val = (Val)op1loc;
					int op1v = op1Val.getValue();
					int op2v = op2Val.getValue();
					value.add(new Val(op1v&op2v));
				}
				else
				{
					value.add(Symbol_Top.getSymbolTop());
				}
			}			
		}
		putElements(op3reg, value);
	}
	
	private void orOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					Val op1Val = (Val)op1loc;
					Val op2Val = (Val)op1loc;
					int op1v = op1Val.getValue();
					int op2v = op2Val.getValue();
					value.add(new Val(op1v | op2v));
				}
				else
				{
					value.add(Symbol_Top.getSymbolTop());
				}
			}			
		}
		putElements(op3reg, value);
	}
	private void xorOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					Val op1Val = (Val)op1loc;
					Val op2Val = (Val)op1loc;
					int op1v = op1Val.getValue();
					int op2v = op2Val.getValue();
					value.add(new Val(op1v ^ op2v));
				}
				else
				{
					value.add(Symbol_Top.getSymbolTop());
				}
			}			
		}
		putElements(op3reg, value);
		
	}
	
	
	private void subOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {

		
		Set<IValue> op1loc=opInit(op1);
		Set<IValue> op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		for(IValue 	o1 : op1loc)
		{
			for(IValue o2 : op2loc)
			{
				value.add( subNAddOperation_(o1,o2, "sub") );
			}
		}
		putElements(op3reg, value);
		
	}
	private void addOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {

		
		Set<IValue> op1loc=opInit(op1);
		Set<IValue> op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		for(IValue 	o1 : op1loc)
		{
			for(IValue o2 : op2loc)
			{
				value.add( subNAddOperation_(o1,o2, "add") );
			}
		}
		putElements(op3reg, value);
		
	}


	
	
	private IValue subNAddOperation_(IValue op1loc, IValue op2loc, String operation) throws MLocException
	{
		int flag = 1;
		if(operation.equals("sub"))
		{
			flag = -1;
		}
		
		
		if(op1loc instanceof Symbol_Top)			
		{
			return Symbol_Top.getSymbolTop();
		}
		if(op1loc instanceof Symbol_Bottom)
		{
			return Symbol_Top.getSymbolTop();
		}
		
		if( ( op1loc instanceof StructuredMLoc )&& (op2loc instanceof Val) )
		{
			
			StructuredMLoc tStruct = ((StructuredMLoc) op1loc).copy();
			int op2v = ((Val)op2loc).getValue()*flag;
			Val t = new Val(tStruct.getC2().getValue() + op2v);
			tStruct.setC2(t);
			
			return tStruct;
		}
		else if((op1loc instanceof IRegister) && (op2loc instanceof Val))
		{
			//reg +- const
			IRegister op1reg = (IRegister) op1loc;
			Val op2val = (Val) op2loc;
			op2val = new Val( op2val.getValue()*flag);
			StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder()
									.reg2(op1reg)
									.c2(op2val).build();
			return tStruct;
		}
		else if((op1loc instanceof Val) && (op2loc instanceof IRegister))
		{
			//const +- reg
			if(operation.equals("add"))
			{
				//const + reg == reg + const
				IRegister op2reg = (IRegister) op2loc;
				Val op1val = (Val) op1loc;
				StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder()
										.reg2(op2reg)
										.c2(op1val).build();
				return tStruct;
			}
			else
			{
				//const - reg -> T
				return Symbol_Top.getSymbolTop();
			}
		}
		
		else if( ( op1loc instanceof Val )&& (op2loc instanceof StructuredMLoc) )
		{
			if(operation.equals("add"))
			{
				StructuredMLoc tStruct = ((StructuredMLoc) op2loc).copy();
				int op1v = ((Val)op1loc).getValue()*flag;
				Val t = new Val(tStruct.getC2().getValue() + op1v);
				tStruct.setC2(t);
				return tStruct;
			}
			else
			{
				return Symbol_Top.getSymbolTop();
			}
		}
		else if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = ((Val)op1loc).getValue();
			int op2v = ((Val)op2loc).getValue();
			return new Val(op1v + op2v*flag);
		}
		return Symbol_Top.getSymbolTop();
	}
	
	
	private void divOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					int op1v = ((Val)op1loc).getValue();
					int op2v = ((Val)op2loc).getValue();
					value.add(new Val(op1v / op2v) );
				}
				else
				{
					value.add( Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
		
	}
	private void modOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					int op1v = ((Val)op1loc).getValue();
					int op2v = ((Val)op2loc).getValue();
					value.add(new Val(op1v % op2v) );
				}
				else
				{
					value.add( Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
		
	}
	
	private void mulOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {
		Set<IValue> op1locs=opInit(op1);
		Set<IValue> op2locs=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		Set<IValue> value = new HashSet<IValue>();
		
		
		for(IValue op1loc : op1locs)
		{
			for(IValue op2loc : op2locs)
			{
				if((op1loc instanceof Val) && (op2loc instanceof Val))
				{
					int op1v = ((Val)op1loc).getValue();
					int op2v = ((Val)op2loc).getValue();
					value.add(new Val(op1v * op2v) );
				}
				else
				{
					value.add( Symbol_Top.getSymbolTop());
				}
			}
		}
		putElements(op3reg, value);
	}
	
	
	private void print(RTable rTable2)
	{
		for(IRegister reg : rTable2.keySet())
		{
			LogConsole.log("Key : "+reg+"\n");
			for(IValue value : rTable2.get(reg))
			{
				LogConsole.log("\tValue : "+value+"\n" );
			}
			
		}
	}

	private Set<IValue> opInit(ReilOperand op)
	{
		OperandType opType = op.getType();
		Set<IValue> oploc=null;
		
		
		if(op.getValue().charAt(0)=='-' && op.getValue().charAt(1)=='t')
		{
			LogConsole.log("opinit :  -tx \n" );
			oploc = new HashSet<IValue>();
			oploc.add(Symbol_Top.getSymbolTop());
			return oploc;			
		}
		
		
		if(opType==OperandType.REGISTER)
		{
			IRegister op1reg = MFactoryHelper.newIRegister(op);
			Set<IValue> op1mapping = getElements(op1reg);
			
			if(op1mapping == null)
			{
				oploc =new HashSet<IValue>();
				oploc.add(Symbol_Bottom.getSymbolBottom());
				return oploc;
			}
			else 
			{
				oploc = op1mapping;
			}

		}
		else if(opType==OperandType.INTEGER_LITERAL)
		{
			oploc =new HashSet<IValue>();
			oploc.add(Val.newVal(op));

		}
		else
		{
			//error
		}
		return oploc;		
	}	
	private void putElement (IRegister key, IValue value)	
	{
		Set<IValue> valueSet = new HashSet<IValue>();		
		valueSet.add(value);		
		rTable.put(key, valueSet);
	}
	private void putElements (IRegister key, Set<IValue> value)	
	{
		if(rTable.containsKey(key))
		{
			rTable.remove(key);
		}
		rTable.put(key, value);
	}

	private void addElement (IRegister key, IValue value)	
	{
		Set<IValue> valueSet = rTable.get(key);
		if(valueSet ==null)
		{
			valueSet = new HashSet<IValue>();
		}
		
		valueSet.add(value);
		
		putElements(key, valueSet);
	}
	
	private Set<IValue> getElements (IRegister key)	
	{
		Set<IValue> valueSet = rTable.get(key);
		if(valueSet ==null)
		{
			valueSet = new HashSet<IValue>();
		}

		return valueSet;
	}
	
	private void clearCallStack(InstructionGraphNode inst)	
	{
		Address funcAddr = inst.getInstruction().getAddress();
		long funcAddrLong = funcAddr.toLong();
		funcAddrLong /= 0x100;
		Instruction nativeInst = ReilInstructionResolve.findNativeInstruction(func, funcAddrLong);
		
		if(callStackFlag)
		{
			clearCallStack_Ebp();
			callStackFlag = false;
		}

		if(nativeInst.getMnemonic().equals("call"))
		{
			callStackFlag = true;
		}

		
	}
	private void clearCallStack_Ebp()
	{
		Set<IValue> values = rTable.get(new ActualReg("esp"));
		Set<IValue> newValues = new HashSet<IValue>();
		for(IValue value : values)
		{
			if(value instanceof StructuredMLoc)
			{
				StructuredMLoc structuredValue = (StructuredMLoc) value;
				env.remove(structuredValue);
				Val ori = structuredValue.getC2();
				Val add4 = new Val(ori.getValue()+4);
				
				
				StructuredMLoc newStructuredValue = structuredValue.copy();
				newStructuredValue.setC2(add4);
				newValues.add(newStructuredValue);
				//rTable.remove(new ActualReg("esp"));
				//rTable.put(new ActualReg("esp"), newValues);
			}
		}
		rTable.remove(new ActualReg("esp"));
		rTable.put(new ActualReg("esp"), newValues);
	}
}

