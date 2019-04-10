package plugin.java.com.plas.crashfilter.util;

import com.google.security.zynamics.binnavi.API.disassembly.FunctionBlock;
import com.google.security.zynamics.binnavi.API.disassembly.Module;
import com.google.security.zynamics.binnavi.API.gui.LogConsole;
import com.google.security.zynamics.binnavi.API.helpers.MessageBox;
import javafx.util.Pair;
import org.javatuples.Triplet;

import java.io.*;
import java.util.*;

public class CrashFileScanner {
    public static int unknownCount = 0;
    public static int knownCount = 0;

    public static Map<Long, CrashPoint> parseCrashFiles(File[] crashFiles, Module module, String crashAddr,
            boolean singleCrashCheck) {

        if (singleCrashCheck) {
            return findFunction(module, crashAddr);
        } else {
            return parseMultiCrashFiles(crashFiles, module, crashAddr);
        }

    }

    public static Map<Long, CrashPoint> findFunction(Module module, String inputAddress) {

        /* �����Է� **/
        Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();
        List<FunctionBlock> fb = module.getCallgraph().getNodes();
        int index = 1;

        Long crashPointAddr = Long.decode(inputAddress);
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

        crashPointToFuncAddr.put(crashPointAddr, new CrashPoint(funcAddr_result, "fileName"));
        LogConsole.log("c \n");

        return crashPointToFuncAddr;

    }

    private static Map<Long, CrashPoint> parseMultiCrashFiles(File[] crashFiles, Module module, String crashAddr) {

        Map<Long, CrashPoint> crashPointToFuncAddr = new HashMap<Long, CrashPoint>();

        for (File crashFile : crashFiles) {
            System.out.println("CrashFiles : key -" + crashFile);
            if (crashFile.canRead()) {

                String s = "";
                BufferedReader in = null;
                try {
                    in = new BufferedReader(new FileReader(crashFile));

                } catch (FileNotFoundException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }

                while (true) {
                    try {
                        s = in.readLine();
                        if (s == null) {
                            break;
                        }
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }

                    crashAddr = s;
                    List<FunctionBlock> fb = module.getCallgraph().getNodes();
                    int index = 1;

                    Long crashPointAddr = Long.decode(crashAddr);
                    LogConsole.log("	crashAddr :  : " + crashPointAddr + " / " + crashAddr + "\n");

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
                        if (i % 50 == 0) {
                            // LogConsole.log(" finding FunctionAddr..... :
                            // "+Long.toHexString(funcAddr_now)+"\n");
                        }
                        if (funcAddr_now > crashPointAddr && funcAddr_before <= crashPointAddr) {
                            funcAddr_result = funcAddr_before;
                            LogConsole.log(
                                    "	!!!!I found it !!!!!!!!!_now : " + Long.toHexString(funcAddr_before) + "\n");
                            break;
                        } else if (funcAddr_now <= crashPointAddr && funcAddr_before > crashPointAddr) {
                            funcAddr_result = funcAddr_now;
                            LogConsole
                                    .log("	!!!!I found it !!!!!!!!!_after : " + Long.toHexString(funcAddr_now) + "\n");
                            break;
                        }
                        funcAddr_before = funcAddr_now;
                    }

                    crashPointToFuncAddr.put(crashPointAddr, new CrashPoint(funcAddr_result, "fileName"));
                    LogConsole.log("c \n");

                }
            }

        }
        for (Long key : crashPointToFuncAddr.keySet()) {
            System.out.println("CrashFileScanner : key -" + key);
        }
        return crashPointToFuncAddr;
    }

    private static boolean parseCrashFile(BufferedReader reader, Map<Long, CrashPoint> crashPointToFuncAddr,
            String fileName) {


        try {

            Long crashPointAddr = Long.decode("0x060849d4");

            Long funcAddr;
            // funcAddr = Long.decode(st.nextToken());
            funcAddr = crashPointToFuncAddr.get(crashPointAddr).getFuncAddr();
            if (crashPointToFuncAddr.put(crashPointAddr, new CrashPoint(funcAddr, fileName)) != null) {
                LogConsole.log("Address already exist\n");
            } else {
                LogConsole.log("ELSE \n");
            }
            MessageBox.showInformation(null, "EE!");

        } catch (Exception e) {
            System.out.println(e.toString());
            MessageBox.showInformation(null, "parseError" + e.toString());
        }

        return true;
    }

    public static ArrayList<Triplet<String, String, String>> parseCallTraceLog(File file){
        //Fisrt is caller function's address, second is point of call.
        ArrayList<Triplet<String, String, String>> calleeCaller = new ArrayList<>();
        //Map<String, ArrayList<Pair<String, String>>> calleeCaller = new HashMap<>();
        BufferedReader br;
        try{
            br = new BufferedReader(new FileReader(file));
            while(br.ready()){
                StringTokenizer st = new StringTokenizer(br.readLine(), ":");
                String caller, callAddress, callee;
                caller = st.nextToken();
                callAddress = st.nextToken();
                callee = st.nextToken();

                Triplet<String, String, String> tri = new Triplet<>(caller, callee, callAddress);
                calleeCaller.add(tri);

            }
            br.close();


        }catch (FileNotFoundException fe){

        } catch (IOException e) {
            e.printStackTrace();
        }
        return calleeCaller;
    }
}
