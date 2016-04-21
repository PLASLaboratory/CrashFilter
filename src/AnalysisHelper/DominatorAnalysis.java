package AnalysisHelper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.security.zynamics.binnavi.API.disassembly.BasicBlock;
import com.google.security.zynamics.binnavi.API.disassembly.BlockEdge;
import com.google.security.zynamics.binnavi.API.disassembly.FlowGraph;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.helpers.GraphAlgorithms;
import com.google.security.zynamics.binnavi.disassembly.IBlockNode;

public class DominatorAnalysis {
	private Function curFunc;
	private FlowGraph flowGraph; 
	private List<BasicBlock> nodes;
	Map<BasicBlock, List<BasicBlock>> dominator = new HashMap<BasicBlock, List<BasicBlock>>();
	Map<BasicBlock, List<BasicBlock>> pdominator = new HashMap<BasicBlock, List<BasicBlock>>();
	
	public DominatorAnalysis(Function curFunction)
	{
		this.curFunc=curFunction;
		this.flowGraph = curFunc.getGraph();
		this.nodes = flowGraph.getNodes();
	}
	
	
	public void fineDominator()
	{
		//LogConsole.log("block count : "+ curFunc.getBlockCount()+"\n");
		
		boolean change = true;
		
		for(BasicBlock key : nodes)
		{
			List<BasicBlock> initList= new ArrayList<BasicBlock>();
			initList.addAll(nodes);  		// list for init 
			dominator.put(key, initList);		// itit. dom(BB) = All Nodes.
		}

		
		List<BasicBlock> entryDom = new ArrayList<BasicBlock>();
		int count = 1;
		
		Map<BasicBlock, List<BasicBlock>> temp = new HashMap<BasicBlock, List<BasicBlock>>();
		while(change)
		{
			
			//LogConsole.log(count+"-+start-+=+=+=+=-"+"\n");
			count++;
			change = false;
			
			
			for(BasicBlock n : nodes)
			{

				List<BasicBlock> pre = getPredecessors(n);
				List<List<BasicBlock>> domList;
				List<BasicBlock> preDom;
			
				if(n == nodes.get(0))
				{
					//LogConsole.log("root : "+n.getAddress()+"\n");
					preDom = entryDom;
				}
				else
				{

					domList = getListsDomList(pre, temp);
					
					int i=0;
					for(List<BasicBlock> tbl : domList)
					{
						i++;
					}
					
				
					preDom  = intersectionBB(domList);	//intersection of predecessor's dominator
					
					for(BasicBlock tbb : preDom)
					{
					//	LogConsole.log("\t"+"pre's dom intersection : "+tbb.getAddress()+"\n");
					}

				
				}
				
				if(!preDom.contains(n))
				{
					preDom.add(n); // + self
				}
				temp.put(n, preDom);
				//LogConsole.log("result\n");
				//printDominator(temp);
			}
			if(!dominator.equals(temp))
			{
				dominator = new HashMap<BasicBlock, List<BasicBlock>>(temp);
				change = true;
				//LogConsole.log("\t"+"change : true"+"\n");
				//temp = new HashMap<BasicBlock, List<BasicBlock>>();
			}
			else
			{
			//	LogConsole.log("\t"+"change : false"+"\n");
			
			}
			
			
			
		}
		printDominator(dominator);
		//LogConsole.log("================= end dom analysis ===================\n");
		
	}
	
	
	
	public void finePDominator()
	{
		//LogConsole.log("block count : "+ curFunc.getBlockCount()+"\n");
		
		boolean change = true;
		
		for(BasicBlock key : nodes)
		{
			List<BasicBlock> initList= new ArrayList<BasicBlock>();
			initList.addAll(nodes);  		// list for init 
			pdominator.put(key, initList);		// itit. dom(BB) = All Nodes.
		}
		
		
		List<BasicBlock> entryDom = new ArrayList<BasicBlock>();
		int count = 1;
		
		Map<BasicBlock, List<BasicBlock>> temp = new HashMap<BasicBlock, List<BasicBlock>>();
		while(change)
		{
			
		//	LogConsole.log(count+"-+start-+=+=+=+=-"+"\n");
			count++;
			change = false;
			
			
			for(int j= nodes.size()-1; j>=0; j--)
			{
				BasicBlock n = nodes.get(j);
			//	LogConsole.log("\n"+"--BB : "+n.getAddress()+"--\n");
				List<BasicBlock> succ = getSuccessors(n);
				
				for(BasicBlock tbb : succ)
				{
				//	LogConsole.log("\t"+"prede : "+tbb.getAddress()+"\n");
				}

				List<List<BasicBlock>> domList;
				List<BasicBlock> succDom;
			
				if(n == nodes.get(nodes.size()-1))
				{
					//LogConsole.log("root : "+n.getAddress()+"\n");
					succDom = entryDom;
				}
				else
				{
					
				
					//LogConsole.log("notroot : "+n.getAddress()+"\n");
					domList = getListsDomList(succ, temp);
					
					int i=0;
					for(List<BasicBlock> tbl : domList)
					{
						//LogConsole.log("\t"+"succ : "+succ.get(i).getAddress()+"\n");
						i++;
						for(BasicBlock tbb : tbl)
						{
							//LogConsole.log("\t\t"+"succ's dom : "+tbb.getAddress()+"\n");
						}
					}
					
				
					succDom  = intersectionBB(domList);	//intersection of predecessor's dominator
					
					for(BasicBlock tbb : succDom)
					{
						//LogConsole.log("\t"+"succ's dom intersection : "+tbb.getAddress()+"\n");
					}

				
				}
				
				if(!succDom.contains(n))
				{
					succDom.add(n); // + self
				}
				temp.put(n, succDom);
				//LogConsole.log("result\n");
				//printDominator(temp);
			}
			if(!pdominator.equals(temp))
			{
				pdominator = new HashMap<BasicBlock, List<BasicBlock>>(temp);
				change = true;
				//LogConsole.log("\t"+"change : true"+"\n");
				//temp = new HashMap<BasicBlock, List<BasicBlock>>();
			}
			else
			{
				//LogConsole.log("\t"+"change : false"+"\n");
			
			}
			
			
			
		}
		printDominator(pdominator);

		
	}
	private void printDominator(Map<BasicBlock, List<BasicBlock>> dominator)
	{
		LogConsole.log("\t--------print-------\n");
		for(BasicBlock key  : dominator.keySet())
		{
			List<BasicBlock> lb = dominator.get(key);
			LogConsole.log(key.getAddress()+"");
			for(BasicBlock b : lb)
			{
				LogConsole.log(":"+b.getAddress());
			}
			LogConsole.log("\n");
			
		}
		LogConsole.log("\t----------------\n");
	}
	
	private List<List<BasicBlock>>getListsDomList(List<BasicBlock> pre, Map<BasicBlock, List<BasicBlock>> temp)
	{
		List<List<BasicBlock>> result = new ArrayList<List<BasicBlock>>();
		for(BasicBlock b : pre)
		{
			if(temp.containsKey(b))
			{
				result.add(temp.get(b));
			}
			
		}
		return result;
	}
	

	private List<BasicBlock> getPredecessors(BasicBlock bb)
	{
		List<BasicBlock> predecessors= new ArrayList<BasicBlock>();
		Iterator < BlockEdge > it = flowGraph.getEdges().iterator();
		while(it.hasNext())
		{
			BlockEdge e = it.next();
			if(e.getTarget().equals(bb))
			{
				predecessors.add(e.getSource());
			}
		}
		
		return predecessors;
	}
	
	private List<BasicBlock>  getSuccessors(BasicBlock bb)
	{
		List<BasicBlock> successors= new ArrayList<BasicBlock>();
		for(BlockEdge e : flowGraph.getEdges())
		{
			if(e.getSource().equals(bb))
			{
				successors.add(e.getTarget());
			}
		}
		
		return successors;
	}
	
	
	
	private List<BasicBlock> intersectionBB(List<List<BasicBlock>> bbs)
	{
		List<BasicBlock> result = new ArrayList<BasicBlock>();
		result.addAll(nodes);		//init. all nodes.

		
		for(List<BasicBlock> list : bbs)
		{
			List<BasicBlock> temp = new ArrayList<BasicBlock>();
			for(BasicBlock bb : list)
			{
				if(result.contains(bb))
				{
					temp.add(bb);
				}
			}
			result = temp;
		}
		
		return result; 
	}
}
