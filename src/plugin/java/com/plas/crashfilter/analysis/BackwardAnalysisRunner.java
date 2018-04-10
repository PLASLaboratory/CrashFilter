package plugin.java.com.plas.crashfilter.analysis;

import com.google.security.zynamics.binnavi.API.disassembly.*;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.API.reil.*;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;
import com.google.security.zynamics.binnavi.standardplugins.utils.Pair;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DeepDefChaining;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefLatticeElement;
import plugin.java.com.plas.crashfilter.analysis.dataflow.DefUseChain;
import plugin.java.com.plas.crashfilter.analysis.dataflow.ReachingDefinition;
import plugin.java.com.plas.crashfilter.analysis.helper.Graph.DefUseGraph;
import plugin.java.com.plas.crashfilter.analysis.helper.Graph.DefUseNode;
import plugin.java.com.plas.crashfilter.analysis.helper.HeapChecker;
import plugin.java.com.plas.crashfilter.analysis.helper.VariableFinder;
import plugin.java.com.plas.crashfilter.analysis.ipa.CallStackCleaner;
import plugin.java.com.plas.crashfilter.analysis.ipa.InterProcedureMode;
import plugin.java.com.plas.crashfilter.analysis.memory.MLocAnalysis;
import plugin.java.com.plas.crashfilter.analysis.memory.MLocLatticeElement;
import plugin.java.com.plas.crashfilter.analysis.memory.mloc.MLocException;

import java.io.*;
import java.util.*;

/**
 * Created by User on 2017-08-30.
 */
public class BackwardAnalysisRunner {
    final private File crashFolder;
    final private PluginInterface m_pluginInterface;
    final private Module module;
    final private String inputAddress;
    final private int optionCode;

    private List<InstructionGraphNode> result;
    private Map<InstructionGraphNode, Set<Pair<InstructionGraphNode, String>>> propagatePath = new LinkedHashMap<>();
    //Map<Long, Pair<Long, Address>> calleeCallerMap;
    Map<String, Pair<String, Address>> calleeCallerMap; //for cve-2017-16829
    Map<Long, List<InstructionGraphNode>> tainted_instructions;
    Map<Long, Long> tainted_instructions_count;
    Map<Long, Boolean> address_expolit;
    Long crashAddress;
    ArrayList<Function> workList;
    long rdaTime = 0;
    long memLocTime = 0;
    long heapTime  = 0;
    long callStackTime = 0;

    private boolean singleCrashCheck = false;

    public BackwardAnalysisRunner(PluginInterface m_pluginInterface, File crashFolder,Module module, String inputAddress, int optionCode) {
        this.crashFolder = crashFolder;
        this.m_pluginInterface = m_pluginInterface;
        this.module = module;
        this.inputAddress = inputAddress;
        this.optionCode = optionCode;
        parseCallGraph();
        tainted_instructions = new HashMap<>();
        tainted_instructions_count = new HashMap<>();
        address_expolit = new HashMap<>();
        makeCallGraph_CVE_17122();
        //makeCallGraph_CVE_9755();
        //makeReadPath_2_29();
        //makeCallGraph_CVE_17122();
        makeReadPath_17122();
        //makeCallGraph_CVE_16830();
        //makeReadPath_16830();
        //makeCallGraph_CVE_16829();
        //makeReadPath_2_29();
    }

    private void decodeOptionCode(int code) {
        singleCrashCheck = ((code & 0x1) == 0x1);
        System.out.println("singleCrashCheck  :" + singleCrashCheck);
    }


    public void run()  throws MLocException, InternalTranslationException{
        decodeOptionCode(this.optionCode);
        ArrayList<Long> crashPointList = this.findFunctionFromCrashPointAddr();
        Map<Long, Boolean> result = new HashMap<Long, Boolean>();
        long beforeTime = System.currentTimeMillis();
        for(Long crashAddr: crashPointList){
            address_expolit.put(crashAddr, false);
            runSingleCrash(crashAddr);

            Set<Long> nativeAddressSet = new HashSet<>();
            List<InstructionGraphNode> tainted_insts = this.tainted_instructions.get(crashAddr);
            for(InstructionGraphNode insts : tainted_insts){
                nativeAddressSet.add(ReilHelpers.toNativeAddress(insts.getInstruction().getAddress()).toLong());
            }
            this.tainted_instructions_count.put(crashAddr, (long) nativeAddressSet.size());
        }
        long afterTime = System.currentTimeMillis();
        long processingTime = afterTime - beforeTime;
        printResult(this.address_expolit, processingTime);
        logTaintedInstruction();
    }

    private ArrayList<Long> findFunctionFromCrashPointAddr() {
        ArrayList<Long> crashPointList = new ArrayList<>();
        if (singleCrashCheck) {
                crashPointList.add(Long.decode(this.inputAddress));
        }
        else{
            if(this.crashFolder.canRead()){
                BufferedReader br = null;
                try {
                    br = new BufferedReader(new FileReader(this.crashFolder));

                } catch (FileNotFoundException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                while(true){
                    String s= null;
                    try {
                        s = br.readLine();
                        if (s == null) {
                            break;
                        }
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    crashPointList.add(Long.decode( s ));
                }
            }
        }
        return crashPointList;
    }
    private void runSingleCrash(Long inputAddress) throws MLocException, InternalTranslationException{
        LogConsole.log("Finding Path Start!\n");
        crashAddress = inputAddress;
        List<InstructionGraphNode> tainted_insts = new ArrayList<>();
        this.tainted_instructions.put(inputAddress, tainted_insts);
        Long functionAddress = findFunction(inputAddress);
        LogConsole.log("Found Function!!");

        Function currentFunction = ModuleHelpers.getFunction(this.module, functionAddress);

        ReilFunction currentReilFunction = getReilFunction(currentFunction);

        LogConsole.log("Create ReilFunctionGraph");
        ReilGraph currentReilFunctionGraph = currentReilFunction.getGraph();
        InstructionGraph currentInstructionGraph = InstructionGraph.create(currentReilFunctionGraph);
        List<InstructionGraphNode> currentInstructionGraphNodes = currentInstructionGraph.getNodes();

        //Tainted instruction List
        List<InstructionGraphNode> inputReilInstrutions = this.getInputInstructionGraphNode(currentInstructionGraphNodes, inputAddress);

        Boolean taintSourceCheck = ((this.optionCode&0x100000) == 0x100000);



        IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;
        try {
            mLocResult =memoryAnalysis(currentInstructionGraph, currentFunction);
        }catch (Exception e){
            e.printStackTrace();
            System.out.println(e.toString());
        }
        VariableFinder vf = new VariableFinder(module, currentFunction);

        if(taintSourceCheck){
            inputReilInstrutions = this.getTaintedInstructionNodes(inputReilInstrutions, vf);
        }

        IStateVector<InstructionGraphNode, DefLatticeElement> rdResult;
        List<Long> virtualCrashAddrs = new ArrayList<>();
        virtualCrashAddrs.add(inputAddress);
        ReachingDefinition rda = new ReachingDefinition(currentInstructionGraph, virtualCrashAddrs, vf);
        Long startTime = System.currentTimeMillis();
        rdResult = rda.runRDAnalysis(InterProcedureMode.NORMAL);
        Long endTime = System.currentTimeMillis();
        this.rdaTime += endTime-startTime;
        System.out.println("End Reaching");
        DefUseChain defUseChain = new DefUseChain(rdResult,currentInstructionGraph, inputAddress, true );
        defUseChain.setMemoryResult(mLocResult);
        defUseChain.defUseChaining();

        this.propagatePath.putAll(defUseChain.getPropagateOp());
        DeepDefChaining deepDefChaining = new DeepDefChaining(currentInstructionGraph, defUseChain, inputReilInstrutions);
        System.out.println("End def use");
        LogConsole.log("Ready Deepdef Chaining!!!\n");

        defUseChain.getDefUseChains();
        deepDefChaining.analysis();

        List<InstructionGraphNode> singleResult = new ArrayList<>();
        List<DefUseGraph> resultGraphList = new ArrayList<>();
        for(InstructionGraphNode inst : inputReilInstrutions) {
            resultGraphList.add(DefUseGraph.createDefUseGraph(deepDefChaining.useDefMap,inst));
        }

        for(DefUseGraph graph : resultGraphList){
            for(DefUseNode node: graph.getNodes()){
                singleResult.add(node.getInst());
            }
        }
        this.tainted_instructions.get(crashAddress).addAll(singleResult);
        LogConsole.log("End DeepDef Chaining\n");
        //DeepDefUse 구현
        //현구의 DefUse 포함관계
        //분석 interface 구현

        //deepDefChaining.printResult();
        backwardAnalysisIPA(currentFunction);
    }

    private void printResult(Map<Long, Boolean> result, long processingTime){
        Calendar cal = Calendar.getInstance();

        int year = cal.get(Calendar.YEAR);
        int mon = cal.get(Calendar.MONTH);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        int hour = cal.get(Calendar.HOUR_OF_DAY);
        int min = cal.get(Calendar.MINUTE);
        int i_cnt = 0;
        int pi_cnt = 0;
        int ni_cnt = 0;
        String fileName = year+"."+mon+"."+day+"_"+hour+"."+min+"_"+module.getName();
        FileOutputStream output;
        try{
            output = new FileOutputStream("D:\\"+fileName+".txt");
            for(Long addr:result.keySet()){
                String outputStr = "0x" + Long.toHexString(addr) + "  :  " + result.get(addr) + "\rtainted instruction counts:"+ this.tainted_instructions_count.get(addr)+"\r\n";
                output.write(outputStr.getBytes());
                if(result.get(addr))
                    i_cnt++;
                else
                    ni_cnt++;
            }
            String outputString = "\r\n" + "I : " + i_cnt + "\r\n";
            outputString += "NI : " + ni_cnt + "\r\n";
            outputString += "Time : "+processingTime+"\r\n";
            outputString += "RDA : "+rdaTime+"\r\n";
            outputString += "mLoc : "+memLocTime+"\r\n";
            output.write(outputString.getBytes());
            output.close();
        }catch (IOException e){
            e.printStackTrace();
        }
    }

    private void logTaintedInstruction(){
        LogConsole.log("=============logTaintedInstruction===========\n");
        Map<InstructionGraphNode, Set<Pair<InstructionGraphNode, String>>> result = new HashMap<>();

        for(List<InstructionGraphNode> insts: tainted_instructions.values()){
            for(InstructionGraphNode inst: insts){
                //LogConsole.log(inst.toString()+"\n");
                if(this.propagatePath.containsKey(inst)) {
                    LogConsole.log("contains KEy \n");

                    Set<Pair<InstructionGraphNode, String>> value = this.propagatePath.get(inst);
                    for(Pair<InstructionGraphNode, String> pair : value){
                        LogConsole.log(pair.first().toString()+"\n");
                    }
                    result.put(inst, value);
                }
            }
        }


        Calendar cal = Calendar.getInstance();

        int year = cal.get(Calendar.YEAR);
        int mon = cal.get(Calendar.MONTH);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        int hour = cal.get(Calendar.HOUR_OF_DAY);
        int min = cal.get(Calendar.MINUTE);
        int i_cnt = 0;
        int pi_cnt = 0;
        int ni_cnt = 0;
        String fileName = year+"."+mon+"."+day+"_"+hour+"."+min+"_"+module.getName()+"_inst_list";
        FileOutputStream output;
        try{
            output = new FileOutputStream("D:\\"+fileName+".txt");
            for(InstructionGraphNode use: result.keySet()){
                String outputString = "";
                Address useAddress = ReilHelpers.toNativeAddress(use.getInstruction().getAddress());

                for(Pair<InstructionGraphNode, String> defAndOp: result.get(use)){
                    Address defAddress = ReilHelpers.toNativeAddress(defAndOp.first().getInstruction().getAddress());
                    if(useAddress.equals(defAddress)) continue;
                    outputString = useAddress.toHexString()+":"+defAddress.toHexString()+":"+defAndOp.second()+"\n";
                    output.write(outputString.getBytes());
                }
            }
            output.close();
        }catch (IOException e){
            e.printStackTrace();
        }

    }

    private List<DefUseGraph> makeGraph(Map<InstructionGraphNode, List<InstructionGraphNode>> resultMap, List<InstructionGraphNode> insts){
        LogConsole.log("Debug makeGraph\n");
        List<DefUseGraph> resultGraphList = new ArrayList<>();
        for(InstructionGraphNode inst : insts) {
            resultGraphList.add(DefUseGraph.createDefUseGraph(resultMap,inst));
        }
        LogConsole.log("Debug makeGraph1\n");

        LogConsole.log("Debug makeGraph2\n");
        return resultGraphList;
    }
    private FunctionBlock findFunctionBlock(Function function){
        FunctionBlock currentFunctionBlock = null;
        List<FunctionBlock> functionList = module.getCallgraph().getNodes();
        for(FunctionBlock functionBlock : functionList){
            if(functionBlock.getFunction().getAddress().toLong()==function.getAddress().toLong()) {
                currentFunctionBlock = functionBlock;
                LogConsole.log("Found Function!\n");
            }
        }
        return currentFunctionBlock;
    }
    private void backwardAnalysisIPA(Function function){
        LogConsole.log("BackwardAnalysisIPA Start!!!\n");
        LogConsole.log("Function Name: "+function.getName()+"\n");

        if(this.workList.contains(function))
             fowardAnalysis(function);

        //We don't use call graph in BinNavi
        //We use call trace.

        if(calleeCallerMap.containsKey(function.getName())){
            LogConsole.log("BackwardAnalysisIPA CALLER CALLEE!!!\n");

            Pair<String, Address> pair = calleeCallerMap.get(function.getName());
            Function parent = findFunction(pair.first());
            List<Instruction> argList = getArgInsts(parent, pair.second());
            for(Instruction inst: argList)
                LogConsole.log(inst.toString());
            try{
                isReachableInput(parent, argList);
            }
            catch(MLocException e){
                System.out.println(e.toString());
            }
        }
    }

    private void fowardAnalysis(Function fb) {
        runForwardAnalysis(fb);
    }

    private void runForwardAnalysis(Function fb){
        workList.remove(fb);
        if(fb.getName().equals("_read")||fb.getName().equals("fread")){
            this.address_expolit.put(this.crashAddress, true);
            return ;
        }
        LogConsole.log("ForwardAnalysis Start!!!\n");
        LogConsole.log("Function Name: "+fb.getName()+"\n");
        Function function = fb;
        if(!function.isLoaded()) {
            try {
                function.load();
            } catch (CouldntLoadDataException e) {
                e.printStackTrace();
            }
        }
        List<Long> virtualCrashAddrs = new ArrayList<>();
        List<InstructionGraphNode> taintedInst = new ArrayList<>();

        virtualCrashAddrs.add(function.getAddress().toLong());
        InstructionGraph iGraph = getReilGraph(function);

        for(Long crashAddr: virtualCrashAddrs){
            taintedInst.addAll (this.getInputInstructionGraphNode(iGraph.getNodes(), crashAddr));
        }
        IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;
        try {
            mLocResult = memoryAnalysis(iGraph, function);
        } catch (MLocException e) {
            e.printStackTrace();
        }
        VariableFinder vf = new VariableFinder(this.module, function);
        IStateVector<InstructionGraphNode, DefLatticeElement> rdResult = null;
        ReachingDefinition rda = new ReachingDefinition(iGraph, virtualCrashAddrs , vf);
        try {
            long startTime = System.currentTimeMillis();
            rdResult = rda.runRDAnalysis(InterProcedureMode.FUNCTIONAnalysis);
            long endTime = System.currentTimeMillis();
            rdaTime += endTime-startTime;
        } catch (MLocException e) {
            e.printStackTrace();
        }
        DefUseChain defUseChain = new DefUseChain(rdResult, iGraph, new Long(0), false);
        defUseChain.setMemoryResult(mLocResult);
        defUseChain.getDefUseChains();

        this.propagatePath.putAll(defUseChain.getPropagateOp());

        //콜지점 알아야되고
        //아규먼트 알아야되고
        LogConsole.log("where?1\n");
        Set<InstructionGraphNode> tainted_inst_set = new HashSet<>();

        List<DefUseChain.DefUseGraph> resultGraph = defUseChain.getDuGraphs();
        LogConsole.log("where?2\n");
        for(DefUseChain.DefUseGraph dug: resultGraph){
            for(DefUseChain.DefUseNode dun :dug.getNodes()){
                taintedInst.add(dun.getInst());
            }
        }

        tainted_inst_set.addAll(taintedInst);
        this.tainted_instructions.get(crashAddress).addAll(tainted_inst_set);

        for(FunctionBlock child : findFunctionBlock(fb).getChildren()){
            if(this.workList.contains(child)){
                runForwardAnalysis(child.getFunction());
            }
        }

        LogConsole.log("Function Name: "+function.getName()+"\n");
        LogConsole.log("ForwardAnalysis End!!!\n");
        if(workList.size()!=0){
            Function nextWork = workList.get(0);
            runForwardAnalysis(nextWork);
        }
    }

    private Function findFunction(Callgraph cg, Long addr){
        for(FunctionBlock fb: cg.getNodes()){
            if(addr.equals(fb.getFunction().getAddress().toLong()))
                return fb.getFunction();
        }
        return null;
    }


    private void isReachableInput(Function function, List<Instruction> argList) throws MLocException{
        LogConsole.log("isReachableInput Start!!!\n");
        LogConsole.log("Function Name: "+function.getName()+"\n");

        if(!function.isLoaded()) {
            try {
                function.load();
            } catch (CouldntLoadDataException e) {
                e.printStackTrace();
            }
        }
        List<Long> virtualCrashAddrs = new ArrayList<>();
        List<InstructionGraphNode> taintedInst = new ArrayList<>();

        for(Instruction inst: argList)
            virtualCrashAddrs.add(inst.getAddress().toLong());
        InstructionGraph iGraph = getReilGraph(function);

        for(Long crashAddr: virtualCrashAddrs){
            taintedInst.addAll (this.getInputInstructionGraphNode(iGraph.getNodes(), crashAddr));
        }
        IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;
        try {
            mLocResult = memoryAnalysis(iGraph, function);
        }catch (MLocException e){
            System.out.println(e.toString());
        }
        LogConsole.log("End Mloc analysis \n");
        VariableFinder vf = new VariableFinder(this.module, function);
        IStateVector<InstructionGraphNode, DefLatticeElement> rdResult;
        ReachingDefinition rda = new ReachingDefinition(iGraph, virtualCrashAddrs , vf);
        long startTime = System.currentTimeMillis();
        rdResult = rda.runRDAnalysis(InterProcedureMode.NORMAL);
        LogConsole.log("End RD analysis \n");
        long endTime = System.currentTimeMillis();
        rdaTime += endTime - startTime;
        DefUseChain defUseChain = new DefUseChain(rdResult, iGraph, new Long(0), false);
        defUseChain.setMemoryResult(mLocResult);
        defUseChain.defUseChaining();
        LogConsole.log("End DU analysis \n");
        this.propagatePath.putAll(defUseChain.getPropagateOp());
        DeepDefChaining deepDefChaining = new DeepDefChaining(iGraph, defUseChain, taintedInst);
        deepDefChaining.analysis();

        //콜지점 알아야되고
        //아규먼트 알아야되고
        LogConsole.log("where?1\n");
        Set<InstructionGraphNode> tainted_inst_set = new HashSet<>();

        List<DefUseGraph> resultGraph = makeGraph(deepDefChaining.useDefMap, taintedInst);
        LogConsole.log("where?2\n");
        for(DefUseGraph dug: resultGraph){
            for(DefUseNode dun :dug.getNodes()){
                taintedInst.add(dun.getInst());
            }
        }

        tainted_inst_set.addAll(taintedInst);
        this.tainted_instructions.get(crashAddress).addAll(tainted_inst_set);
        LogConsole.log("Function Name: "+function.getName()+"\n");
        LogConsole.log("isReachableInput End!!!\n");
        backwardAnalysisIPA(function);
    }

    private InstructionGraph getReilGraph(Function function){
        ReilFunction currentReilFunction = null;
        try {
            currentReilFunction = function.getReilCode();
        } catch (InternalTranslationException e) {
            e.printStackTrace();
        }
        ReilGraph currentReilGraph = currentReilFunction.getGraph();
        InstructionGraph currentInstructionGraph = InstructionGraph.create(currentReilGraph);
        return currentInstructionGraph;
    }
//    private IStateVector<InstructionGraphNode, DefLatticeElement> retrunRdResult(Function function){
//        IStateVector<InstructionGraphNode, DefLatticeElement> rdResult;
//        VariableFinder
//
//        return rdResult;
//    }
    //this function not use now
    private boolean includeSystemCall(Function function){
        //함수에 시스템콜이 포함되어 있는지 찾음...
        //찾으면 시스템콜이 포함되어 있는 베이직블록과 그 상의 List index를 리턴
        //그렇지 않으면 null 리턴
        //모든 함수가 이 분석을 수행
//        List<BasicBlock> bbs = function.getGraph().getNodes();
//        for( BasicBlock bb: bbs) {
//            List<Instruction> insts = bb.getInstructions();
//            for (int i = 0; i < insts.size(); i++) {
//                Instruction inst = insts.get(i);
//                if (inst.getMnemonic().contains("call")) {
//                    for (Operand op : inst.getOperands()) {
//                        if (op.toString().contains("read")) {
//                            Pair<BasicBlock, Integer> pairReturn = new Pair<>(bb, i);
//                            return true;
//                        }
//                    }
//                }
//            }
//        }
//        return false;

        List<FunctionBlock> children = findFunctionBlock(function).getChildren();
        for(FunctionBlock fb: children){
            if(fb.getFunction().getName().contains("read")||fb.getFunction().getName().contains("fread")) {
                LogConsole.log("INclude : "+fb.getFunction().getName()+"\n");
                return true;
            }
        }
        return false;
    }
    //not use
    private List<Instruction> getCallBasicBlock(Function f, String fName){
        LogConsole.log("getCallBasicBlock Debug \n");
        if(!f.isLoaded()) {
            try {
                f.load();
            } catch (CouldntLoadDataException e) {
                e.printStackTrace();
            }
        }
        ArrayList<Instruction> callReverseInsts = new ArrayList<>();
        for(BasicBlock bb : f.getGraph().getNodes()){
            for(Instruction inst : bb.getInstructions()){
                callReverseInsts.add(inst);
                if(inst.getMnemonic().contains("call")){
                    for(Operand op : inst.getOperands()) {
                        if (op.toString().contains(fName)) {
                            LogConsole.log("Found!!!!\n");
                            LogConsole.log("End getCallBasicBlock Debug\n");
                            Collections.reverse(callReverseInsts);
                            return callReverseInsts;
                        }
                    }
                }
            }
        }
        LogConsole.log("Can't Found it. End getCallBasicBlock Debug\n");
        return null;
    }
    private List<Instruction> getCallBasicBlock(Function f, Address address){
        LogConsole.log("getCallBasicBlock Debug \n");
        if(!f.isLoaded()) {
            try {
                f.load();
            } catch (CouldntLoadDataException e) {
                e.printStackTrace();
            }
        }
        ArrayList<Instruction> callReverseInsts = new ArrayList<>();
        for(BasicBlock bb : f.getGraph().getNodes()){
            for(Instruction inst : bb.getInstructions()){
                callReverseInsts.add(inst);
                if(inst.getAddress().equals(address)){
                            Collections.reverse(callReverseInsts);
                            return callReverseInsts;
                }

            }
        }
        LogConsole.log("Can't Found it. End getCallBasicBlock Debug\n");
        return null;
    }
    private List<Instruction> getArgInsts(List<Instruction> insts){
        //Argument 가 직접적으로 사용된 instruction
        ArrayList<Instruction> resultList = new ArrayList<>();
        //delete call points
        insts.remove(0);
        for(int i = 0 ; i < 5; i ++)
            resultList.add(insts.get(i));

        return resultList;
    }

    private List<Instruction> getArgInsts(Function parent, Address address){
        //Argument 가 직접적으로 사용된 instruction
        LogConsole.log("In Function getArgInsts\n");
        if(!parent.isLoaded()) try {
            parent.load();
        } catch (CouldntLoadDataException e) {
            e.printStackTrace();
        }
        List<Instruction> instList = getCallBasicBlock(parent, address);
        return getArgInsts(instList);
    }

    private boolean checkOperandisArg(Instruction inst){
        for(Operand op : inst.getOperands())
            LogConsole.log(op.toString());
        LogConsole.log("\n\n");

        if(inst.getOperands().size()<1)
            return false;
        if(inst.getMnemonic().equals("push")) return true;
        return inst.getOperands().get(0).toString().contains("esp");
    }


    private List<InstructionGraphNode> getInputInstructionGraphNode(List<InstructionGraphNode> instructionGraphNodes, Long inputAddress){
        List<InstructionGraphNode> inputReilinstructions = new ArrayList<>();
        for (InstructionGraphNode instructionGraphNode: instructionGraphNodes){
            Address instructionAddress = ReilHelpers.toNativeAddress(instructionGraphNode.getInstruction().getAddress());
            if(instructionAddress.toLong() == inputAddress)
                inputReilinstructions.add(instructionGraphNode);
        }
        return inputReilinstructions;
    }

    private void printResult(List<InstructionGraphNode> resultInstructionGraphNodes){
        LogConsole.log("Logging Start!");
        Set<String> resultInstructionGraphNodesSet = new HashSet<>();
        for(InstructionGraphNode node: resultInstructionGraphNodes) {
            Address nativeAddress = ReilHelpers.toNativeAddress(node.getInstruction().getAddress());
            resultInstructionGraphNodesSet.add(nativeAddress.toHexString());
        }
        List<String> resultAddresses = new ArrayList<>();
        resultAddresses.addAll(resultInstructionGraphNodesSet);
        Collections.sort(resultAddresses);
        try{
            FileWriter fw = new FileWriter("d:/test.txt");
            for(String address : resultAddresses)
                fw.write(address+"\r\n");
            fw.close();
        }catch(IOException e){

        }
    }
    private ReilFunction getReilFunction(Function function) {
        ReilFunction reilFunction = null;
        try {
            if(!function.isLoaded())
                function.load();
        } catch (CouldntLoadDataException e) {
            e.printStackTrace();
        }
        LogConsole.log("Created ReilFunction");
        try {
            reilFunction = function.getReilCode();
        }catch (InternalTranslationException e){

        }
        return reilFunction;
    }

    private Long findFunction(Long inputAddress){
        List<FunctionBlock> fb = module.getCallgraph().getNodes();

        Long crashPointAddr = inputAddress;
        LogConsole.log("	inputAddress :  : " + crashPointAddr + " / " + inputAddress + "\n");

        Long funcAddr_before = fb.get(0).getFunction().getAddress().toLong();
        Long funcAddr_now = 0l;
        Long funcAddr_result = 0l;
        List<Long> addr_list = new ArrayList();

        for (int i = 0; i < fb.size(); i++) {
            addr_list.add(fb.get(i).getFunction().getAddress().toLong());
        }
        Collections.sort(addr_list);

        funcAddr_before = addr_list.get(0);
        for (int i = 1; i < addr_list.size(); i++) {

            funcAddr_now = addr_list.get(i);
            // LogConsole.log(" finding FunctionAddr..... :
            // "+Long.toHexString(funcAddr_now)+"\n");

            if (funcAddr_now > crashPointAddr && funcAddr_before <= crashPointAddr) {
                funcAddr_result = funcAddr_before;
                LogConsole.log("	!!!!I found it !!!!!!!!!_now : " + Long.toHexString(funcAddr_before) + "\n");
                break;
            } else if (funcAddr_now <= crashPointAddr && funcAddr_before > crashPointAddr) {
                funcAddr_result = funcAddr_now;
                LogConsole.log("	!!!!I found it !!!!!!!!!_after : " + Long.toHexString(funcAddr_now) + "\n");
                break;
            }
            funcAddr_before = funcAddr_now;
        }

        return funcAddr_result;

    }
    private Function findFunction(String fName){
        Callgraph cg = this.module.getCallgraph();
        for(FunctionBlock fb : cg.getNodes()){
            if(fb.getFunction().getName().equals(fName))
                return fb.getFunction();
        }
        LogConsole.log("Cannot Found function : in findFunction(String fName)\n");
        System.out.println("Cannot Found function : in findFunction(String fName)\n");
        for(StackTraceElement st :Thread.currentThread().getStackTrace()){
            System.out.println(st.toString()+"\n");
        }
        return null;

    }

    private List<InstructionGraphNode> getTaintedInstructionNodes (List<InstructionGraphNode> taintedInstruction, VariableFinder vf){
        List<InstructionGraphNode> resultNodes = new ArrayList<>();
        InstructionGraphNode node = taintedInstruction.get(taintedInstruction.size()-1);
        resultNodes.add(node);
        return resultNodes;
    }
    private IStateVector<InstructionGraphNode, MLocLatticeElement> memoryAnalysis(
            ILatticeGraph<InstructionGraphNode> graph, Function curFunc) throws MLocException {
        LogConsole.log("Function Name in Memory ANalysis" + curFunc.getName()+"\n");
        // TODO Auto-generated method stub
        Long startTime = System.currentTimeMillis();
        IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult;
        LogConsole.log("== start locAnalysis analysis ==\n");

        LogConsole.log("== find Heap Location ==\n");
        Long heapStart = System.currentTimeMillis();

        Long heapEnd = System.currentTimeMillis();
        heapTime += heapEnd - heapStart;

        Long callStackStart = System.currentTimeMillis();
        Long callStackEnd = System.currentTimeMillis();
        MLocAnalysis mLocAnalysis = new MLocAnalysis(graph, curFunc);
        callStackTime += callStackEnd - callStackStart;

        LogConsole.log("== analysis start ==\n");
        mLocResult = mLocAnalysis.mLocAnalysis();
        LogConsole.log("== where? ==\n");
        mLocAnalysis.deleteTempReg(mLocResult);
        mLocAnalysis.deleteBottomSymbol(mLocResult);
        LogConsole.log("== end memoryAnalysis ==\n");
        // envAnalysis.printEnv(envResult);
        // LogConsole.log("== end print env analysis ===\n");
        Long endTime = System.currentTimeMillis();
        memLocTime += endTime-startTime;
        return mLocResult;

    }


    private void parseCallGraph(){
        //for binutil2.29
        //callee's name is key. value is pair that are function name and call point.
        /*
        calleeCallerMap = new HashMap<>();
        Pair<Long, Address> fp0 = new Pair<>(new Long(0x808e590), new Address(0x808fc66));
        Pair<Long, Address> fp1 = new Pair<>(new Long(0x804ca00), new Address(0x804d5fb));
        Pair<Long, Address> fp2 = new Pair<>(new Long(0x809d160), new Address(0x809d189));
        Pair<Long, Address> fp3 = new Pair<>(new Long(0x8096BF0 ), new Address(0x8096c09));
        calleeCallerMap.put(new Long(0x8090990), fp0);
        calleeCallerMap.put(new Long(0x808e590), fp1);
        calleeCallerMap.put(new Long(0x804ca00), fp2);
        calleeCallerMap.put(new Long(0x0804BEB0), fp2);
        calleeCallerMap.put(new Long(0x8096ED0), fp3);*/
    }



    private void makeCallGraph(){
        //for binutil2.28
/*
        calleeCallerMap = new HashMap<>();
        Pair<Long, Address> fp0 = new Pair<>(new Long(0x804e480), new Address(0x808fc66));

        calleeCallerMap.put(new Long(0x804bef3), fp0);*/
    }

    private void makeReadPath(){
        //objdump2.29.1
        Callgraph cg = this.module.getCallgraph();
        FunctionBlock _read = null;
        for(FunctionBlock fb : cg.getNodes()){
            if(fb.getFunction().getName().equals("_read")) {
                _read = fb;
                break;
            }
        }
        this.workList = new ArrayList<>();


        LogConsole.log("===Print work list:  ===\n");


        this.workList.add(findFunction("display_any_bfd"));
        this.workList.add(findFunction("dump_bfd"));
        this.workList.add(findFunction("disassemble_section"));
        this.workList.add(findFunction("try_print_file_open"));
        this.workList.add(findFunction("_read"));

        for(Function fb: this.workList){
            LogConsole.log(fb.getName()+"\n");
        }
        LogConsole.log("===End Print work list:  ===\n");

    }
    private void makeReadPath_2_29(){
        //objdump2.29
        Callgraph cg = this.module.getCallgraph();

        this.workList = new ArrayList<>();


        LogConsole.log("===Print work list:  ===\n");

        this.workList.add(findFunction("disassemble_section"));
        this.workList.add(findFunction("try_print_file_open"));
        this.workList.add(findFunction("_read"));

        for(Function fb: this.workList){
            LogConsole.log(fb.getName()+"\n");
        }
        LogConsole.log("===End Print work list:  ===\n");

    }
    private void makeReadPath_17122(){
        //objdump2.29
        Callgraph cg = this.module.getCallgraph();

        this.workList = new ArrayList<>();


        LogConsole.log("===Print work list:  ===\n");



        this.workList.add(findFunction("display_any_bfd"));
        this.workList.add(findFunction("dump_bfd"));
        this.workList.add(findFunction("disassemble_section"));
        this.workList.add(findFunction("try_print_file_open"));
        this.workList.add(findFunction("_read"));
        for(Function fb: this.workList){
            LogConsole.log(fb.getName()+"\n");
        }
        LogConsole.log("===End Print work list:  ===\n");

    }
    private void makeReadPath_16830(){
        //objdump2.29
        Callgraph cg = this.module.getCallgraph();

        this.workList = new ArrayList<>();


        LogConsole.log("===Print work list:  ===\n");

        this.workList.add(findFunction("main"));
        this.workList.add(findFunction("process_object"));
        this.workList.add(findFunction("fread"));
        for(Function fb: this.workList){
            LogConsole.log(fb.getName()+"\n");
        }
        LogConsole.log("===End Print work list:  ===\n");

    }
    private void getParents(FunctionBlock fb, List<FunctionBlock> fbList){
        fbList.add(fb);
        for(FunctionBlock parent: fb.getParents()){
            getParents(parent, fbList);
            if(parent.getFunction().getName().equals("main")) return;
        }
    }


    //for CVE-2017-16829
    private void makeCallGraph_CVE_16829(){
        //for 2.29.1
        //for CVE-2017-16828
        //call trace
        //main->display_file->display_object_bfd->bfd_check_format_matches->bfd_elf32_object_p->bfd_section_from_shdr
        // ->_bfd_elf_make_section_from_shdr->elf_parse_notes->elf_obj_grok_gnu_note->_bfd_elf_parse_gnu_properties
        //key is callee and value is pair that caller and call point
        //elf_obj_grok_gnu_note is inner function (not exist in binary codes)
        //disply_object_bfd is inner function
        Map<String, Pair<String, Address>> calleeCallerMap = new HashMap<>();
        Pair<String, Address> fp = new Pair<>("_bfd_elf_parse_gnu_properties", new Address(0x80d6743));
        Pair<String, Address> fp0 = new Pair<>("elf_parse_notes", new Address(0x80b9b54));
        Pair<String, Address> fp1 = new Pair<>("_bfd_elf_make_section_from_shdr", new Address(0x80bdfde));
        Pair<String, Address> fp2 = new Pair<>("bfd_section_from_shdr", new Address(0x80bc93d));
        Pair<String, Address> fp3 = new Pair<>("bfd_elf32_object_p", new Address(0x80ac7de));
        Pair<String, Address> fp4 = new Pair<>("bfd_check_format_matches", new Address(0x8095b0f));
        Pair<String, Address> fp5 = new Pair<>("display_any_bfd", new Address(0x804f84d));
        Pair<String, Address> fp6 = new Pair<>("display_file", new Address(0x804f966));
        Pair<String, Address> fp7 = new Pair<>("main", new Address(0x805020e));
        calleeCallerMap.put("bfd_getl32", fp);
        calleeCallerMap.put("_bfd_elf_parse_gnu_properties", fp0);
        calleeCallerMap.put("elf_parse_notes", fp1);
        calleeCallerMap.put("_bfd_elf_make_section_from_shdr", fp2);
        calleeCallerMap.put("bfd_section_from_shdr", fp3);
        calleeCallerMap.put("bfd_elf32_object_p", fp4);
        calleeCallerMap.put("bfd_check_format_matches", fp5);
        calleeCallerMap.put("display_any_bfd", fp6);
        calleeCallerMap.put("display_file", fp7);
        this.calleeCallerMap = calleeCallerMap;
    }


    private void makeCallGraph_CVE_9755(){
        //for 2.29.1
        //for CVE-2017-9755
        //call trace
        Map<String, Pair<String, Address>> calleeCallerMap = new HashMap<>();
        Pair<String, Address> fp0 = new Pair<>("print_insn", new Address(0x808FC66));
        Pair<String, Address> fp1 = new Pair<>("disassemble_section", new Address(0x804D5FB ));
        Pair<String, Address> fp2 = new Pair<>("bfd_map_over_sections", new Address(0x809D189));
        Pair<String, Address> fp3 = new Pair<>("dump_bfd", new Address(0x804F35B));
        Pair<String, Address> fp4 = new Pair<>("display_any_bfd", new Address(0x804f99b));
        Pair<String, Address> fp5 = new Pair<>("display_file", new Address(0x804fa7b));
        Pair<String, Address> fp6 = new Pair<>("main", new Address(0x805031e));

        calleeCallerMap.put("OP_G", fp0);
        calleeCallerMap.put("print_insn", fp1);
        calleeCallerMap.put("disassemble_section", fp2);
        calleeCallerMap.put("bfd_map_over_sections", fp3);
        calleeCallerMap.put("dump_bfd", fp4);
        calleeCallerMap.put("dispaly_any_bfd", fp5);
        calleeCallerMap.put("display_file", fp6);


        this.calleeCallerMap = calleeCallerMap;
    }

    private void makeCallGraph_CVE_17122(){
        //for 2.29.1
        //for CVE-2017-9755
        //call trace
        Map<String, Pair<String, Address>> calleeCallerMap = new HashMap<>();
        Pair<String, Address> fp0 = new Pair<>("coff_real_object_p", new Address(0x8100743 ));
        Pair<String, Address> fp1 = new Pair<>("pe_bfd_object_p", new Address(0x80ef029 ));//
        Pair<String, Address> fp2 = new Pair<>("bfd_check_format_matches", new Address(0x8095b0f));
        Pair<String, Address> fp3 = new Pair<>("display_any_bfd", new Address(0x804f84d));
        Pair<String, Address> fp4 = new Pair<>("display_file", new Address(0x805031e));
        Pair<String, Address> fp5 = new Pair<>("main", new Address(0x805020e));

        calleeCallerMap.put("styp_to_sec_flags", fp0);//
        calleeCallerMap.put("coff_real_object_p", fp1);//z
        calleeCallerMap.put("pe_bfd_object_p", fp2);
        calleeCallerMap.put("bfd_check_format_matches", fp3);
        calleeCallerMap.put("display_any_bfd", fp4);
        calleeCallerMap.put("display_file", fp5);

        this.calleeCallerMap = calleeCallerMap;
    }

    private void makeCallGraph_CVE_16830(){
        //for 2.29.1
        //for CVE-2017-9755
        //call trace
        Map<String, Pair<String, Address>> calleeCallerMap = new HashMap<>();
        Pair<String, Address> fp0 = new Pair<>("process_object", new Address(0x807e357));
        Pair<String, Address> fp1 = new Pair<>("main", new Address(0x8082824 ));
        calleeCallerMap.put("sub_809DBB0", fp0);
        calleeCallerMap.put("process_object", fp1);
        this.calleeCallerMap = calleeCallerMap;
    }
}
