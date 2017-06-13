package plugin.java.com.plas.crashfilter.analysis.memory.mloc;

public class TempLoc implements IMLoc {
	static int final_num=0; // k_i
	private int num = 0;
	
	private TempLoc(int n){num = n;}
	int getNum(){ return num;}
	
	public static TempLoc getNextTempLoc(){
		TempLoc t = new TempLoc(final_num);
		final_num++;
		return t;
	}
	
	public MLocTypes getMLocType(){ return MLocTypes.TempLocK;}
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		
		return "[TempLoc :"+num+"]";
	}
	
}
