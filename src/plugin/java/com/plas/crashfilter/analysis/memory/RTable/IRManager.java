package plugin.java.com.plas.crashfilter.analysis.memory.RTable;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.OperandType;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.ReilOperand;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import plugin.java.com.plas.crashfilter.analysis.helper.AddressTransferHelper;
import plugin.java.com.plas.crashfilter.analysis.helper.MFactoryHelper;
import plugin.java.com.plas.crashfilter.analysis.memory.IALoc;
import plugin.java.com.plas.crashfilter.analysis.memory.IValue;
import plugin.java.com.plas.crashfilter.analysis.memory.Val;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.*;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.ActualReg;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.IRegister;
import plugin.java.com.plas.crashfilter.analysis.memory.regs.TempReg;
import plugin.java.com.plas.crashfilter.util.ReilInstIndex;

import java.util.*;

public class IRManager { // singleton
	HashMap<IRegister, IValue> rTable = null;
	
	int count;
	private ILatticeGraph<InstructionGraphNode> reilGraph ;
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
	
	private IRManager()
	{
		rTable = new HashMap<IRegister, IValue>();
		count = 0;
		init();
	}
	
	private void init() {
		IRegister init_esp = null ;
		StructuredMLoc init_stack = null ;
		IRegister init_ebp = null ;
		StructuredMLoc init_oldebp = null;
		try {
			
			//init esp-> stack0
			init_esp =  new ActualReg("esp");			
			init_stack =  new StructuredMLoc.StructuredMLocBuilder()
						.reg2(new ActualReg("stack"))
						.c2(new Val(0)).build();

			rTable.put(init_esp, init_stack );
			
			
			//init ebp-> old ebp			
			init_ebp =  new ActualReg("ebp");

			init_oldebp =  new StructuredMLoc.StructuredMLocBuilder()
									.reg2(new ActualReg("oldebp"))
									.c2(new Val(0)).build();
			
			rTable.put(init_ebp, init_oldebp );
			
			//print(rTable);
		

		} catch (MLocException e) {
			e.printStackTrace();
		}
		
	}

	static IRManager IRMGR = null;
	public static IRManager getIRManager(){
		
		
		
		if (IRMGR != null)
			return IRMGR;
		else
			return new IRManager();
	}
	public void setGraph(ILatticeGraph<InstructionGraphNode> graph)
	{
		reilGraph= graph;
	}
	
	void oneReilInst(ReilInstruction inst) throws MLocException{

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
		for (InstructionGraphNode inst : reilGraph.getNodes())
		{

			if(inst.getInstruction().getAddress().toLong()% 0x100 == 0)
			{
					deleteTempRegster();
			}
			LogConsole.log(inst.getInstruction().toString()+"\n");

			
			try {
				oneReilInst(inst.getInstruction());
			} catch (MLocException e) {
				e.printStackTrace();
			}
			print(rTable);
			
			LogConsole.log("--------------------\n");
		}
		
		deleteTempRegster();
		LogConsole.log("-----------end---------\n");
	}
	
	private void deleteTempRegster()
	{
		
		LogConsole.log("-----------------------delete temp start\n");
		List<IALoc> toBeRemoved = new ArrayList<IALoc>();
		Set<IRegister> keyset = rTable.keySet();
		for(IRegister key : keyset)
		{
			if(key instanceof TempReg)
			{
				LogConsole.log("tempreg : "+key+"  is deleted\n");
				toBeRemoved.add(key);
			}

			
		}
		for ( IALoc key: toBeRemoved ) {
			rTable.remove(key);
		}
		
		LogConsole.log("-----------------------delete temp end\n");
	}
	
	
	private void biszOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		int op1v=-1;					//op1v can have 0 or 1 only.  
		IValue value = null;
		if(op1.getType() == OperandType.REGISTER)
		{
			IRegister op1reg = MFactoryHelper.newIRegister(op1);
			IValue temp = rTable.get(op1);
			if(temp instanceof IRegister)
			{
				//imposible
			}
			else if (temp instanceof Val)
			{
				op1v = ((Val)temp).getValue();
			}
		}
		else if(op1.getType() == OperandType.INTEGER_LITERAL)
		{
			op1v = AddressTransferHelper.hexString2Int(op1.getValue());
		}
		else
		{
		}
		
		if(op1v == -1)
		{
			//bisz err
		}
		else
		{
			value = new Val( op1v == 0? 1:0 );
			rTable.put(op3reg, value);
		}
		
	}
	private void bshOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		//If the second operand is positive, the shift is a left-shift. 
		//If the second operand is negative, the shift is a right-shift. 
		
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if(op2.getValue().equals("0"))
		{			
			strOperation(op1,op2,op3);
		}
		else if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = bshCalc( op1v,  op2v);
			rTable.put(op3reg, value);
		}
		else 
		{
			rTable.put(op3reg, Symbol_Top.getSymbolTop());
		}
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
		IValue op1loc=opInit(op1);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		if(op1.getType() == OperandType.REGISTER)
		{
			IRegister op1reg = MFactoryHelper.newIRegister(op1); 
			value = rTable.get(op1reg);
		}
		else if(op1.getType() == OperandType.INTEGER_LITERAL)
		{
			int t = AddressTransferHelper.hexString2Int(op1.getValue());
			value = new Val(t);
		}
		
		rTable.put(op3reg, op1loc);
	}
	private void stmOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		
		IValue op3reg = opInit(op3); 
		if(!(op3reg instanceof IRegister))
		{
			//cannot store
			//M[M[op3]] => M[ notRegister ]  = op1 (x)     this case
			//M[M[op3]] => M[ Register ]  = op1    (o)
			return;
		}
		else
		{
			if(op1.getType() == OperandType.REGISTER)
			{
				IRegister op1reg = MFactoryHelper.newIRegister(op1);	
				rTable.put( (IRegister)op3reg , (IValue)op1reg );			
			}
			else if(op1.getType() == OperandType.INTEGER_LITERAL)
			{
				int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
				Val op1val = new Val(op1v);
				rTable.put( (IRegister)op3reg , op1val);
			}
		}
		
	}
	
	private void ldmOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IValue op1loc=opInit(op1);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		
		if(op1.getType() == OperandType.REGISTER)
		{
			rTable.put( op3reg , op1loc );			
		}
		else
		{
			//operand�� Literal�̸� �޸��ּҰ��� �ǹ�. �װ��� ��������°��� �Ұ���.
		}
		
	}
	
	private void andOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if(op2.getValue().equals("4294967295"))
		{			
			strOperation(op1,op2,op3);
			return;
			//value = replace2StackReg( ((IValue)op1loc) );
			//rTable.put(op3reg, (value));		
		}
		else if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = new Val(op1v&op2v);
			rTable.put(op3reg, value);
		}
		else
		{
			rTable.put(op3reg, Symbol_Top.getSymbolTop());
		}
		
	}
	
	private void orOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = new Val(op1v|op2v);
			rTable.put(op3reg, value);
		}
		else
		{
			rTable.put(op3reg,Symbol_Top.getSymbolTop());
		}
	}
	private void xorOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException
	{
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = new Val(op1v ^ op2v);
			rTable.put(op3reg, value);
		}
		else
		{
			rTable.put(op3reg, Symbol_Top.getSymbolTop());
		}
		
	}
	
	
	private void subOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {

		
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
	

		IValue value = subNAddOperation_(op1loc,op2loc, "sub");
		rTable.put(op3reg, value);
		
	}
	private void addOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {

		
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
	
		IValue value = subNAddOperation_(op1loc,op2loc, "add");
		rTable.put(op3reg, value);
		
	}


	
	
	private IValue subNAddOperation_(IValue op1loc, IValue op2loc, String operation) throws MLocException
	{
		int flag = 1;
		if(operation.equals("sub"))
		{
			flag = -1;
		}
		else if (operation.equals("add"))
		{			
		}
		else
		{
			System.out.println("IRManager - subNAddOperation_ : err\n");
		}
		
		
		
		if((op1loc instanceof IRegister) && (op2loc instanceof Val))
		{
			IRegister op1reg = (IRegister) op1loc;
			Val op2val = (Val) op2loc;
			StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder()
									.reg2(op1reg)
									.c2(op2val).build();
										
		}
		else if((op1loc instanceof Val) && (op2loc instanceof IRegister))
		{
			IRegister op2reg = (IRegister) op2loc;
			Val op1val = (Val) op1loc;
			StructuredMLoc tStruct = new StructuredMLoc.StructuredMLocBuilder()
									.reg2(op2reg)
									.c2(op1val).build();
		}
		else if( ( op1loc instanceof StructuredMLoc )&& (op2loc instanceof Val) )
		{
			StructuredMLoc tStruct = ((StructuredMLoc) op1loc).copy();
			int op2v = ((Val)op2loc).getValue()*flag;
			Val t = new Val(tStruct.getC2().getValue() + op2v);
			tStruct.setC2(t);
			return tStruct;
		}
		else if( ( op1loc instanceof Val )&& (op2loc instanceof StructuredMLoc) )
		{
			StructuredMLoc tStruct = ((StructuredMLoc) op2loc).copy();
			int op1v = ((Val)op1loc).getValue()*flag;
			Val t = new Val(tStruct.getC2().getValue() + op1v);
			tStruct.setC2(t);
			return tStruct;
		}
		else if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			return Val.sub(((Val)op1loc), ((Val)op2loc));
		}
		return null;
	}
	
	
	private void divOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = new Val(op1v / op2v);
			rTable.put(op3reg, value);
		}
		else
		{
			rTable.put(op3reg, Symbol_Top.getSymbolTop());
		}
		
	}
	private void mulOperation(ReilOperand op1, ReilOperand op2, ReilOperand op3) throws MLocException {
		IValue op1loc=opInit(op1);
		IValue op2loc=opInit(op2);
		IRegister op3reg = MFactoryHelper.newIRegister(op3); 
		IValue value = null;
		
		if((op1loc instanceof Val) && (op2loc instanceof Val))
		{
			int op1v = AddressTransferHelper.hexString2Int(op1.getValue());
			int op2v = AddressTransferHelper.hexString2Int(op2.getValue());
			value = new Val(op1v * op2v);
			rTable.put(op3reg, value);
		}
		else
		{
			rTable.put(op3reg,Symbol_Top.getSymbolTop());
		}
	}
	
	
	private void print(HashMap<IRegister, IValue> table)
	{
		for(IRegister reg : table.keySet())
		{
			LogConsole.log("Key : "+reg+"\n");
			LogConsole.log("\tValue : "+table.get(reg)+"\n" );
		}
	}

	public IValue searchRTable(IMLoc imloc)
	{		
		return rTable.get(imloc);
	}
	public IValue replace2StackReg(IValue reg)
	{
		IValue replace = null;
		if(reg instanceof IRegister)
		{			
			if(! (reg.equals(ActualReg.ESP) || reg.equals(ActualReg.EBP)) )
			{
				replace = rTable.get(reg);
			}
		}
		return replace;
		
	}

	private IValue opInit(ReilOperand op)
	{
		OperandType opType = op.getType();
		IValue oploc=null;
		
		if(opType==OperandType.REGISTER)
		{
			IRegister op1reg = MFactoryHelper.newIRegister(op);
			IValue op1mapping = rTable.get(op1reg);
			
			if(op1mapping == null)
			{
				return Symbol_Bottom.getSymbolBottom();
			}
			else 
			{
				oploc = op1mapping;
			}

		}
		else if(opType==OperandType.INTEGER_LITERAL)
		{
			oploc = Val.newVal(op);
		}
		else
		{
			//error
		}
		return oploc;
		
	}	
}
