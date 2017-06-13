package plugin.java.com.plas.crashfilter.analysis.helper;

public class AddressTransferHelper {
    public static int hexString2Int(String str) {
        long longTemp = Long.valueOf(str);
        int result = (int) (longTemp & 0x00000000ffffffff);
        return result;
    }
}
