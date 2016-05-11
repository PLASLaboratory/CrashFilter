package helper;

import com.google.security.zynamics.binnavi.API.gui.LogConsole;

public class MemoryCounter {
    private int numOfStackMemory;
    private int numOfHeapMemory;
	
	
	private static MemoryCounter memoryCounter;
	
	private MemoryCounter()
	{
		numOfStackMemory = 0;
		numOfHeapMemory = 0;
	}
	public static MemoryCounter getMemoryCounter()
	{
		if(memoryCounter == null)
		{
			memoryCounter = new MemoryCounter();
			return memoryCounter;
		}
		else
		{
			return memoryCounter;
		}
	}
	public void printMemoryCounter()
	{
		LogConsole.log("numOfStackMemory : " + numOfStackMemory+"\n");
		LogConsole.log("numOfHeapMemory : " + numOfHeapMemory+"\n");
	}
	
	public void countStack()
	{
		numOfStackMemory++;
	}
	public void countHeap()
	{
		numOfHeapMemory++;
	}
}
