package staticAnalysis;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import com.google.security.zynamics.binnavi.API.disassembly.Address;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntLoadDataException;
import com.google.security.zynamics.binnavi.API.disassembly.CouldntSaveDataException;
import com.google.security.zynamics.binnavi.API.disassembly.Function;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariable;
import com.google.security.zynamics.binnavi.API.disassembly.GlobalVariablesManager;
import com.google.security.zynamics.binnavi.API.disassembly.Instruction;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.disassembly.ModuleHelpers;
import com.google.security.zynamics.binnavi.API.disassembly.Operand;
import com.google.security.zynamics.binnavi.API.disassembly.PartialLoadException;
import com.google.security.zynamics.binnavi.API.disassembly.View;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.helpers.IProgressThread;
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
import crashfilter.va.MLocAnalysis.RTable.RTableLatticeElement;
import crashfilter.va.MLocAnalysis.env.EnvLatticeElement;
import crashfilter.va.memlocations.MLocException;
import data.CountInstructionHashMap;
import data.CrashPoint;
import data.ReilInstructionResolve;
import helper.CallStackCleaner;
import helper.CrashFileScanner;
import helper.CrashSourceAdder;
import helper.HeapChecker;
import helper.VariableFinder;
import staticAnalysis.RDAnalysis.RDLatticeElement;
import view.ExploitPathView;

public class AnalysisStartThread implements IProgressThread {
    final private File crashFolder;
    final private PluginInterface m_pluginInterface;
    final private Module module;
    private Map<String, String> crashFilteringResult = new HashMap<>();

    private String crashAddr = ""; 
    boolean singleCrashCheck = false;
    boolean memoryAnalysisCheck = false;
    boolean crashSrcAnalysis = false;

    int e_path_cnt = 0;
    int pe_path_cnt = 0;
    int callCounter = 0;

    public AnalysisStartThread(PluginInterface m_plugin, File crachFolder, Module module, String crashAddr,
            int optionalCode) {
        super();
        this.module = module;
        System.out.println(module.getFilebase());
        this.m_pluginInterface = m_plugin;
        this.crashFolder = crachFolder;
        this.crashAddr = crashAddr;
        decodeOptioalCode(optionalCode);
    }

    private void decodeOptioalCode(int code) {
        singleCrashCheck = (code & 1) == 1;
        memoryAnalysisCheck = (code & 10) == 10;
        crashSrcAnalysis = (code & 100) == 100;

    }



    @Override
    public void run() throws MLocException {
        // TODO Auto-generated method stub
        ILatticeGraph<InstructionGraphNode> graph = null;
        IStateVector<InstructionGraphNode, RDLatticeElement> RDResult = null;
        IStateVector<InstructionGraphNode, RTableLatticeElement> locResult = null;
        IStateVector<InstructionGraphNode, EnvLatticeElement> envResult = null;
        IStateVector<InstructionGraphNode, MLocLatticeElement> mLocResult = null;
        
        Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();
        findFunctionFromCrashPointAddr(crashPointToFuncAddr);
        
        LogConsole.log("Parsing File Number : " + crashPointToFuncAddr.size() + "\n\n");

        HashSet<Long> count = new HashSet<>();
        List<String> tobeInterprocedureAnalysis = new ArrayList<>();
        CountInstructionHashMap cihm = new CountInstructionHashMap();
        int viewIndex = 0;

        for (Long crashPointAddress : crashPointToFuncAddr.keySet()) {

            crashAddr = Long.toHexString(crashPointAddress);

            LogConsole.log("now analyzing : " + Long.toHexString(crashPointAddress) + "\n");
            long before = System.currentTimeMillis();

            ReilFunction curReilFunc = null;
            List<ReilInstruction> crashReilInst = new ArrayList<ReilInstruction>();
            List<InstructionGraphNode> crashInstructionGraphNode = new ArrayList<InstructionGraphNode>();
            Function curFunc = ModuleHelpers.getFunction(module,
                    crashPointToFuncAddr.get(crashPointAddress).getFuncAddr());
            // Function curFunc = ModuleHelpers.getFunction(module, 33760);

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

            // Translate function to REIL function
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

            /**********************
             * Dominator Analysis*********************************
             * 
             * DominatorAnalysis domAnalysis = new DominatorAnalysis(curFunc);
             * LogConsole.log("Dom:\n"); domAnalysis.fineDominator();
             * LogConsole.log("PDom\n"); domAnalysis.finePDominator(); //
             * LogConsole.log("\n"); /
             *****************************************************************************/

            if (curReilFunc != null) {
                graph = InstructionGraph.create(curReilFunc.getGraph()); // API's
                                                                         // Structure
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
            /*********** MLocAnalysis_RTable+Env ********************/
            if (memoryAnalysisCheck) {
                mLocResult = memoryAnalysis(graph, curFunc, mLocResult);
            }
            /*******************************************************/

            System.out.println("== start EEEEEEEEEEEEEEE ==\n");
            RDAnalysis rda = new RDAnalysis(graph, crashPointAddress);
            RDResult = rda.RDAnalysis();

            LogConsole.log("== end rd analysis ==\n");

            LogConsole.log("==start du analysis  1==\n");
            DefUseChain du = new DefUseChain(RDResult, graph, crashPointAddress, crashSrcAnalysis);

            du.setMemoryResult(mLocResult);
            du.defUseChaining();

            if (crashSrcAnalysis) {
                crashInstructionGraphNode.add(CrashSourceAdder.getInstruction(graph, crashPointAddress));
            }
            for (InstructionGraphNode instGraphNode : crashInstructionGraphNode) {
                du.createDefUseGraph(instGraphNode);
            }

            LogConsole.log("== end DU analysis ==\n");

            ExploitableAnalysis ea = new ExploitableAnalysis(du.getDuGraphs(), curFunc, crashPointAddress,
                    crashFilteringResult);
            if (ea.isExploitable()) {
                Map<Instruction, List<Instruction>> exploitPaths = ea.getExploitArmPaths();

                if (!exploitPaths.isEmpty()) {
                    View view = module.createView(curFunc.getName(), String.format("[%d], %s", viewIndex,
                            crashPointToFuncAddr.get(crashPointAddress).getfileName()));
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
            e_path_cnt += ea.getTotal_e_count();
            pe_path_cnt += ea.getTotal_pe_count();

            LogConsole.log("==========end Exploitable analysis ===========\n");
            long after = System.currentTimeMillis();
            long processingTime = after - before;

            LogConsole.log(curFunc.getName() + "-- time : " + processingTime + "\n");
            viewIndex++;

            // how many 'call' instruction in function
            callCounter = getNumOfFunctionCalls(graph, curFunc);
            if (hasFunctionCalls(graph, curFunc)) {
                tobeInterprocedureAnalysis.add(crashAddr);
            }

            InterBBAnalysis interBBAnalysis = new InterBBAnalysis(module, curFunc);

        }

        LogConsole.log(cihm.toString());

        int e_cnt = 0;
        int pe_cnt = 0;
        int ne_cnt = 0;
        for (String str : crashFilteringResult.keySet()) {
            System.out.println("0x" + str + "  :  " + crashFilteringResult.get(str));
            if (crashFilteringResult.get(str).equals("E"))
                e_cnt++;
            if (crashFilteringResult.get(str).equals("PE"))
                pe_cnt++;
            if (crashFilteringResult.get(str).equals("NE"))
                ne_cnt++;
        }

        System.out.println("Exploitable Analysis");
        System.out.println("E," + e_cnt);
        System.out.println("PE, " + pe_cnt);
        System.out.println("NE, " + ne_cnt);
        System.out.println("total: " + (e_cnt + pe_cnt + ne_cnt));

        System.out.println("count of E and PE path");
        System.out.println("E: " + e_path_cnt);
        System.out.println("PE: " + pe_path_cnt);
        System.out.println("total: " + (e_path_cnt + pe_path_cnt));

        System.out.println("call Count : " + callCounter);

        for (String str : tobeInterprocedureAnalysis) {
            //System.out.println("0x" + str);
        }

        System.out.println("=============test============");

        System.out.println();
        System.out.println();
    }

    private void findFunctionFromCrashPointAddr(Map<Long, CrashPoint> crashPointToFuncAddr) {
        File[] subDirs;
        if (crashFolder != null && crashFolder.isDirectory()) {

            subDirs = crashFolder.listFiles();

            LogConsole.log("Folder count: " + Integer.toString(subDirs.length) + "\n");

            boolean multiCrashAnalysis = !singleCrashCheck;
            if (multiCrashAnalysis) {
                crashPointToFuncAddr
                        .putAll(CrashFileScanner.parseCrashFiles(subDirs, module, crashAddr, singleCrashCheck));
                LogConsole.log("path   : \n");
                LogConsole.log("filter : \n");
            } else {
                //LogConsole.log("error multi crash check1 \n");
                return;
            }
        } else {
            if (singleCrashCheck) {
                crashPointToFuncAddr
                        .putAll(CrashFileScanner.parseCrashFiles(null, module, crashAddr, singleCrashCheck));
                LogConsole.log("path   : \n");
                LogConsole.log("filter : \n");
            } else {
                //LogConsole.log("error single crash check2 \n");
                return;
            }

        }
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

    private int getNumOfFunctionCalls(ILatticeGraph<InstructionGraphNode> graph, Function curFunc) {

        boolean flag = false;
        for (InstructionGraphNode inst : graph.getNodes()) {
            Address instAddr = inst.getInstruction().getAddress();
            long instAddrLong = instAddr.toLong();
            instAddrLong /= 0x100;
            Instruction nativeInst = ReilInstructionResolve.findNativeInstruction(curFunc, instAddrLong);

            if (nativeInst.getMnemonic().equals("call")) {
                callCounter++;
                break;
            } else if (nativeInst.getMnemonic().equals("BL")) {
                for (Operand oprand : nativeInst.getOperands()) {
                    if (oprand.toString().contains("sub_")) {
                        callCounter++;
                        flag = true;
                        break;
                    }
                }
                if (flag) {
                    flag = false;
                    break;
                }
            }
        }
        return callCounter;
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

    @Override
    public boolean close() {
        // TODO Auto-generated method stub
        return false;
    }


}
