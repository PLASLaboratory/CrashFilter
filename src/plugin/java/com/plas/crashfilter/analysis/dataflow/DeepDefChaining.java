package plugin.java.com.plas.crashfilter.analysis.dataflow;

import com.google.common.graph.Network;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;

/**
 * Created by User on 2017-09-01.
 */
public class DeepDefChaining  {
    InstructionGraph instructionGraph;
    DefUseChain defUseChain;
    public Map<InstructionGraphNode, List<InstructionGraphNode>> useDefMap;
    private List<InstructionGraphNode> result;
    private Set<InstructionGraphNode> resultSet;
    private List<InstructionGraphNode> inputInstructions;
    private void printResultSet(){
        for (InstructionGraphNode traceNode: resultSet        ) {
            LogConsole.log(traceNode.getInstruction().getAddress().toHexString()+"\n");
        }
    }
    public DeepDefChaining(InstructionGraph instructionGraph, DefUseChain defUseChain,List<InstructionGraphNode> input) {
        this.inputInstructions = input;
        this.instructionGraph = instructionGraph;
        this.defUseChain = defUseChain;
    }

    private void printDefUse(){
        //For Debugging!!!
        Map<InstructionGraphNode, List<InstructionGraphNode>> defUseMap= defUseChain.getDefUseChains();
        Map<String, Set<String>> nativeDefUseMap = new HashMap<>();
        LogConsole.log("==================================================");
        for (InstructionGraphNode defNode : defUseMap.keySet()){
            LogConsole.log(defNode.toString()+"->");
            for(InstructionGraphNode useNode : defUseMap.get(defNode))
                LogConsole.log(useNode.toString()+";");
            LogConsole.log("\n");
        }
        LogConsole.log("==================================================");
    }
    public void analysis(){
        createUseDefChain();
        Set<InstructionGraphNode> inputSet = new HashSet<>(this.inputInstructions);
        resultSet = new HashSet<>();
        getDeepDefSet(inputSet);
        //this.result = new ArrayList<>(this.resultSet);
        LogConsole.log("End DeepDef analysis\n");
    }
    public Set<String> getDDG(){
        LogConsole.log("===================Print GRAPH!!!!!!!!!!!!!====================\n");
        try{
            FileWriter fw = new FileWriter("d:/ddg.txt");
            for(String edge : this.defUseChain.ddgEdges)
                fw.write(edge+"\r\n");
            fw.close();
        }catch(IOException e){

        }
        return this.defUseChain.ddgEdges;
    }
    public List<InstructionGraphNode> getResult(){
        return this.result;
    }

    private void getDeepDefSet(Set<InstructionGraphNode> uses){
        LogConsole.log("Call getDeepDefSet!!!\n");

        for(InstructionGraphNode useInstruction: uses){
            this.getDefSet(useInstruction);
        }
        LogConsole.log("end getDeepDefSet!!!\n");
    }

    private void getDefSet(InstructionGraphNode use){
        this.resultSet.add(use);
        if(this.useDefMap.containsKey(use)) {
            for (InstructionGraphNode def : this.getDef(use)) {
                getDefSet(def);
            }
        }
    }
    private List<InstructionGraphNode> getDef(InstructionGraphNode use){
        return this.useDefMap.get(use);
    }
    private void createUseDefChain(){
        //useDefMaP의 value를 List로 하는 이유: add 같은 산술명령어 때문
        Map<InstructionGraphNode, List<InstructionGraphNode>> useDefMap= new HashMap<>();
        Map<InstructionGraphNode, List<InstructionGraphNode>> defUseMap= defUseChain.getDefUseChains();
        for(InstructionGraphNode def: defUseMap.keySet()){
            List<InstructionGraphNode> uses = defUseMap.get(def);
            for(InstructionGraphNode use: uses){
                if(useDefMap.containsKey(use)){
                    useDefMap.get(use).add(def);
                } else{
                    List<InstructionGraphNode> defs = new ArrayList<>();
                    defs.add(def);
                    useDefMap.put(use, defs);
                }
            }
        }
        this.useDefMap = useDefMap;
    }

    public void printUseDef(){
        LogConsole.log("Print UseDef Chain\n");
        for(InstructionGraphNode use: this.useDefMap.keySet()){
            LogConsole.log(use.getInstruction().getAddress().toHexString()+"<-");
            for(InstructionGraphNode def: this.useDefMap.get(use))
                LogConsole.log(def.getInstruction().getAddress().toHexString()+" ");
            LogConsole.log("\n");
        }
        LogConsole.log("End Print Usedef Chain\n");

    }

    public void printResult(){
        LogConsole.log("Print Result!!!!\n");
        for(InstructionGraphNode trace: this.result){
            LogConsole.log(trace.getInstruction().getAddress().toHexString()+":\t"+trace.getInstruction().toString()+"\n");
        }
        LogConsole.log("End print result\n");
    }
}
