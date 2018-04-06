package plugin.java.com.plas.crashfilter.analysis.ipa;

public enum InterProcedureMode {

    NORMAL(0), FUNCTIONAnalysis(1);

    private int modeNumber;

    InterProcedureMode(int modeNumber) {
        this.setModeNumber(modeNumber);
    }

    public int getModeNumber() {
        return modeNumber;
    }

    public void setModeNumber(int modeNumber) {
        this.modeNumber = modeNumber;
    }

}
