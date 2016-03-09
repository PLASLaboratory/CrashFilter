package data;
public class CrashPoint {
	private long funcAddr;
	private String fileName;
	
	public CrashPoint(long funcAddr, String fileName){
		this.funcAddr = funcAddr;
		this.fileName = fileName;
	}
	
	public long getFuncAddr(){
		return funcAddr;
	}
	
	public String getfileName(){
		return fileName;
	}
}