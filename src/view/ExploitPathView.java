package view;
import java.awt.Color;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.security.zynamics.binnavi.API.disassembly.EdgeType;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.View;
import com.google.security.zynamics.binnavi.API.disassembly.ViewNode;


public class ExploitPathView {
	Map<Instruction, List<Instruction>> exploitPaths;
	
	public ExploitPathView(Map<Instruction, List<Instruction>> exploitPaths){
		this.exploitPaths = exploitPaths;
	}
	
	
	private void createExploitPathView(View view, List<Instruction> exploitPath){
		Iterator<Instruction> iter = exploitPath.iterator();
		
		//Create head node
		List<Instruction> headCodeList = new ArrayList<Instruction>();
		headCodeList.add(iter.next());
		ViewNode preNode = view.createCodeNode(null, headCodeList);
		preNode.setBorderColor(Color.ORANGE);
		
		//create tail node
		while(iter.hasNext()){
			
			List<Instruction> codeList = new ArrayList<Instruction>();
			codeList.add(iter.next());
			ViewNode nextNode = view.createCodeNode(null, codeList);
			
			//create edge
			view.createEdge(preNode, nextNode, EdgeType.JumpUnconditional);
			
			preNode = nextNode;
			
			if(!iter.hasNext()){
				nextNode.setBorderColor(Color.RED);
			}
		}
	}
	
	public View createExploitPathView(View view){
		
		for(Instruction exploitPoint : exploitPaths.keySet()){
			createExploitPathView(view, exploitPaths.get(exploitPoint));
		}
		
		
		return view;
	}
	
}
