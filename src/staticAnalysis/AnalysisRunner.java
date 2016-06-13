package staticAnalysis;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntLoadDataException;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntSaveDataException;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.ModuleHelpers;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.disassembly.PartialLoadException;
import com.google.security.zynamics.binnavi.API.disassembly.View;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.helpers.MessageBox;
import com.google.security.zynamics.binnavi.API.plugins.PluginInterface;
import com.google.security.zynamics.binnavi.API.reil.InternalTranslationException;
import com.google.security.zynamics.binnavi.API.reil.ReilBlock;
import com.google.security.zynamics.binnavi.API.reil.ReilFunction;
import com.google.security.zynamics.binnavi.API.reil.ReilHelpers;
import com.google.security.zynamics.binnavi.API.reil.ReilInstruction;
import com.google.security.zynamics.binnavi.API.reil.mono.ILatticeGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.IStateVector;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraph;
import com.google.security.zynamics.binnavi.API.reil.mono.InstructionGraphNode;

import crashfilter.va.MLocAnalysis.MLocAnalysis;
import crashfilter.va.MLocAnalysis.MLocLatticeElement;
import crashfilter.va.memlocations.MLocException;
import data.CountInstructionHashMap;
import data.CrashPoint;
import data.ReilInstructionResolve;
import helper.CallStackCleaner;
import helper.CrashFileScanner;
import helper.CrashSourceAdder;
import helper.HeapChecker;
import helper.InterProcedureMode;
import helper.VariableFinder;
import staticAnalysis.RDAnalysis.RDLatticeElement;
import view.ExploitPathView;

public class AnalysisRunner {
    final private File crashFolder;
    final private PluginInterface m_pluginInterface;
    final private Module module;
    private Map<String, String> crashFilteringResult = new HashMap<>();

    private String crashAddr = "";
    boolean singleCrashCheck = false;
    boolean memoryAnalysisCheck = false;
    boolean crashSrcAnalysis = false;

    private int e_path_cnt = 0;
    private int pe_path_cnt = 0;
    private int callCounter = 0;
    private int e_cnt;
    private int pe_cnt;
    private int ne_cnt;
    private int totalTime = 0;
    private int optionCode;
    
    public AnalysisRunner(PluginInterface m_plugin, File crachFolder, Module module, String crashAddr, int optionCode) {
        
        this.module = module;
        this.optionCode = optionCode;
        System.out.println(module.getFilebase());
        this.m_pluginInterface = m_plugin;
        this.crashFolder = crachFolder;
        this.crashAddr = crashAddr;
        decodeOptionCode(optionCode);
    }

    private void decodeOptionCode(int code) {
        singleCrashCheck = (code & 1) == 1;
        memoryAnalysisCheck = (code & 10) == 10;
        crashSrcAnalysis = (code & 100) == 100;

    }
    void runAnalysis(InterProcedureMode interProcedureAnalysisMode) throws MLocException {

        Map<Long, CrashPoint> crashPointToFuncAddr = findFunctionFromCrashPointAddr();
        CountInstructionHashMap cihm = new CountInstructionHashMap();
        

        for (Long crashPointAddress : crashPointToFuncAddr.keySet()) {

            ILatticeGraph<InstructionGraphNode> graph = null;
            IStateVector<InstructionGraphNode, RDLatticeElement> RDResult = null;
            IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;

            LogConsole.log("Parsing File Number : " + crashPointToFuncAddr.size() + "\n\n");

            List<String> tobeInterprocedureAnalysis = new ArrayList<>();
            int viewIndex = 0;

            crashAddr = Long.toHexString(crashPointAddress);

            LogConsole.log("now analyzing : " + Long.toHexString(crashPointAddress) + "\n");
            long before = System.currentTimeMillis();

            ReilFunction curReilFunc = null;
            List<ReilInstruction> crashReilInst = new ArrayList<ReilInstruction>();
            List<InstructionGraphNode> taintSourceInstructionGraphNodes = new ArrayList<InstructionGraphNode>();
            Function curFunc = ModuleHelpers.getFunction(module,
                    crashPointToFuncAddr.get(crashPointAddress).getFuncAddr());
            // Function curFunc = ModuleHelpers.getFunction(module, 33760);

            Instruction crashInst = checkFunctionLoaded(cihm, crashPointAddress, curFunc);

            // Translate function to REIL function
            graph = translateFunc2ReilFunc(graph, curReilFunc, crashReilInst, taintSourceInstructionGraphNodes, curFunc,
                    crashInst);

            /************* MLocAnalysis_RTable+Env ********************/
            if (memoryAnalysisCheck) {
                mLocResult = memoryAnalysis(graph, curFunc, mLocResult);
            }

            /*********** is needed to InterBBANalysis ********************/

            InterBBAnalysis interBBAnalysis = new InterBBAnalysis(module, curFunc);

            /*
             * if (!interBBAnalysis.needAnalysis()) { System.out.println(
             * "NNNNNNNNNNNNNNNNNNNNNO : "+Long.toHexString(crashPointAddress)+
             * "   : "+ ++numOf); }
             * 
             * 
             */

            System.out.println("== start EEEEEEEEEEEEEEE ==\n");
            VariableFinder vf = new VariableFinder(module, curFunc);
            RDAnalysis rda = new RDAnalysis(graph, crashPointAddress, vf);

            RDResult = rda.runRDAnalysis(interProcedureAnalysisMode);
            // rda.printRD(RDResult);
            LogConsole.log("== end rd analysis ==\n");

            LogConsole.log("==start du analysis  1==\n");
            DefUseChain du = new DefUseChain(RDResult, graph, crashPointAddress, crashSrcAnalysis);

            du.setMemoryResult(mLocResult);
            du.defUseChaining();

            if (crashSrcAnalysis) {
                // TODO
                // multiple add
                if (interProcedureAnalysisMode != InterProcedureMode.NORMAL) {
                    taintSourceInstructionGraphNodes.clear();
                }
                taintSourceInstructionGraphNodes.addAll(
                        CrashSourceAdder.getInstructions(graph, crashPointAddress, interProcedureAnalysisMode, vf));
            }
            for (InstructionGraphNode taintSourceInstructionGraphNode : taintSourceInstructionGraphNodes) {
                du.createDefUseGraph(taintSourceInstructionGraphNode);
            }

            LogConsole.log("== end DU analysis ==\n");
            TaintSink ea = new ExploitableAnalysis(du.getDuGraphs(), curFunc, crashPointAddress, crashFilteringResult);
            TaintSink returnValueAnalysis = new ReturnValueAnalysis(du.getDuGraphs(), curFunc, crashFilteringResult,
                    RDResult, graph);
   
            switch (interProcedureAnalysisMode) {
            case NORMAL:
                if (ea.isTaintSink()) {
                    makeView(crashPointToFuncAddr, viewIndex, crashPointAddress, curFunc, ea);
                }
                break;
            case FUNCTIONAnalysis:
                if (returnValueAnalysis.isTaintSink()) {
                    makeView(crashPointToFuncAddr, viewIndex, crashPointAddress, curFunc, returnValueAnalysis);
                }
                break;
            case GVAnalysis:
                break;
            default:
                break;

            }

            e_path_cnt += ea.getTotal_e_count();
            pe_path_cnt += ea.getTotal_pe_count();

            LogConsole.log("==========end Exploitable analysis ===========\n");
            long after = System.currentTimeMillis();
            long processingTime = after - before;

            LogConsole.log(curFunc.getName() + "-- time : " + processingTime + "\n\n");
            totalTime += processingTime;
            viewIndex++;

            if (hasFunctionCalls(graph, curFunc)) {
                tobeInterprocedureAnalysis.add(crashAddr);
            }
        }
        AnalysisStartThread analysisStartThread = new AnalysisStartThread(m_pluginInterface, crashFolder, module ,crashAddr, optionCode);
        
        
        
        LogConsole.log(cihm.toString());

        countExploitableCrash();
        printExploitableCount(e_cnt, pe_cnt, ne_cnt);
        printExploitablePathCount();
        // System.out.println("call Count : " + callCounter);
        LogConsole.log("total time : " + totalTime + "\n");
    }    

    private void makeView(Map<Long, CrashPoint> crashPointToFuncAddr, int viewIndex, Long crashPointAddress,
            Function curFunc, TaintSink taintSink) {
        Map<Instruction, List<Instruction>> exploitPaths = taintSink.getExploitArmPaths();

        if (!exploitPaths.isEmpty()) {
            View view = module.createView(curFunc.getName(),
                    String.format("[%d], %s", viewIndex, crashPointToFuncAddr.get(crashPointAddress).getfileName()));
            try {
                view.load();
            } catch (CouldntLoadDataException e1) {
                e1.printStackTrace();
            } catch (PartialLoadException e1) {
                e1.printStackTrace();
            }
            ExploitPathView exploitView = new ExploitPathView(exploitPaths);
            exploitView.createExploitPathView(view);
            try {
                view.save();
            } catch (CouldntSaveDataException e1) {
                e1.printStackTrace();
            }

        }
    }

    private ILatticeGraph<InstructionGraphNode> translateFunc2ReilFunc(ILatticeGraph<InstructionGraphNode> graph,
            ReilFunction curReilFunc, List<ReilInstruction> crashReilInst,
            List<InstructionGraphNode> crashInstructionGraphNode, Function curFunc, Instruction crashInst) {
        try {
            curReilFunc = curFunc.getReilCode();
        } catch (InternalTranslationException translationException) {
            MessageBox.showException(m_pluginInterface.getMainWindow().getFrame(), null,
                    "Translation ERROR : TO REIL Graph");
        }

        for (ReilBlock block : curReilFunc.getGraph().getNodes()) {

            for (ReilInstruction inst : block.getInstructions()) {

                if (ReilHelpers.toNativeAddress(inst.getAddress()).equals(crashInst.getAddress())) {
                    crashReilInst.add(inst);
                    // LogConsole.log(inst.toString()+"\n");
                }
            }
        }

        if (curReilFunc != null) {
            graph = InstructionGraph.create(curReilFunc.getGraph()); // API's
                                                                     // structure

            for (InstructionGraphNode instGraphNode : graph.getNodes()) {
                for (ReilInstruction reilInst : crashReilInst) {
                    if (instGraphNode.getInstruction().getAddress().equals(reilInst.getAddress())) {
                        crashInstructionGraphNode.add(instGraphNode);
                        // LogConsole.log(instGraphNode.getInstruction().toString()+"\n");
                        break;
                    }
                }
            }
        }
        return graph;
    }

    private Instruction checkFunctionLoaded(CountInstructionHashMap cihm, Long crashPointAddress, Function curFunc) {
        try {
            if (!curFunc.isLoaded()) {
                curFunc.load();
            }
        } catch (CouldntLoadDataException e1) {
            e1.printStackTrace();
            // continue;
        } catch (Exception e1) {
            System.out.println("dubugging" + "/");
            // continue;
        }

        Instruction crashInst = ReilInstructionResolve.findNativeInstruction(curFunc, crashPointAddress);

        if (curFunc == null) {
            System.out.println("function null!!!!");
        }
        if (crashInst == null) {
            System.out.println("instruction null!!!!");
        } else {
            LogConsole.log(crashInst.toString() + "\n");
            StringTokenizer st = new StringTokenizer(crashInst.toString(), " ");
            st.nextToken();
            cihm.put(st.nextToken(), 1);
        }
        return crashInst;
    }

    private void countExploitableCrash() {
        e_cnt = 0;
        pe_cnt = 0;
        ne_cnt = 0;

        FileOutputStream output;
        try {
            output = new FileOutputStream("d:/FilteredCrash.txt");

            for (String str : crashFilteringResult.keySet()) {
                String outputStr = "0x" + str + "  :  " + crashFilteringResult.get(str) + "\r\n";
                System.out.print(outputStr);
                output.write(outputStr.getBytes());
                if (crashFilteringResult.get(str).equals("E"))
                    e_cnt++;
                if (crashFilteringResult.get(str).equals("PE"))
                    pe_cnt++;
                if (crashFilteringResult.get(str).equals("NE"))
                    ne_cnt++;

            }
            output.close();

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    private void printExploitablePathCount() {
        System.out.println("count of E and PE path");
        System.out.println("E: " + e_path_cnt);
        System.out.println("PE: " + pe_path_cnt);
        System.out.println("total: " + (e_path_cnt + pe_path_cnt));
    }

    private void printExploitableCount(int e_cnt, int pe_cnt, int ne_cnt) {
        System.out.println("Exploitable Analysis");
        System.out.println("E," + e_cnt);
        System.out.println("PE, " + pe_cnt);
        System.out.println("NE, " + ne_cnt);
        System.out.println("total: " + (e_cnt + pe_cnt + ne_cnt));
    }

    private Map<Long, CrashPoint> findFunctionFromCrashPointAddr() {
        Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();        
        
        File[] subDirs;
        if (crashFolder != null && crashFolder.isDirectory()) {
            subDirs = crashFolder.listFiles();
            LogConsole.log("Folder count: " + Integer.toString(subDirs.length) + "\n");            
            if(singleCrashCheck)
            {
                subDirs = null;
            }
            crashPointToFuncAddr.putAll(CrashFileScanner.parseCrashFiles(subDirs, module, crashAddr, singleCrashCheck));
            LogConsole.log("path   : \n");
            LogConsole.log("filter : \n");
            
        }
        return crashPointToFuncAddr;
    }

    private boolean hasFunctionCalls(ILatticeGraph<InstructionGraphNode> graph, Function curFunc) {
        boolean hasCall = false;
        for (InstructionGraphNode inst : graph.getNodes()) {
            Address instAddr = inst.getInstruction().getAddress();
            long instAddrLong = instAddr.toLong();
            instAddrLong /= 0x100;
            Instruction nativeInst = ReilInstructionResolve.findNativeInstruction(curFunc, instAddrLong);

            if (nativeInst.getMnemonic().equals("call")) {
                hasCall = true;
                break;
            } else if (nativeInst.getMnemonic().equals("BL")) {
                for (Operand oprand : nativeInst.getOperands()) {
                    if (oprand.toString().contains("sub_")) {
                        hasCall = true;
                        break;
                    }
                }
            }
        }
        return hasCall;
    }

    private IStateVector<InstructionGraphNode, MLocLatticeElement> memoryAnalysis(
            ILatticeGraph<InstructionGraphNode> graph, Function curFunc,
            IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult) throws MLocException {
        // TODO Auto-generated method stub
        LogConsole.log("== start locAnalysis analysis ==\n");

        LogConsole.log("== find Heap Location ==\n");
        HeapChecker.initHeapChecker(graph, curFunc);

        CallStackCleaner callStackCleaner = CallStackCleaner.getCallStackCleaner();
        callStackCleaner.initCallStackCleaner(curFunc, graph);

        MLocAnalysis mLocAnalysis = new MLocAnalysis(graph, curFunc);

        LogConsole.log("== analysis start ==\n");
        mLocResult = mLocAnalysis.mLocAnalysis();
        mLocAnalysis.deleteTempReg(mLocResult);
        mLocAnalysis.deleteBottomSymbol(mLocResult);
        LogConsole.log("== end memoryAnalysis ==\n");
        // envAnalysis.printEnv(envResult);
        // LogConsole.log("== end print env analysis ===\n");

        return mLocResult;

    }

}
