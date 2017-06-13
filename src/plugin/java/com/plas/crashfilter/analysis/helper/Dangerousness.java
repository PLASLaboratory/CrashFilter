package plugin.java.com.plas.crashfilter.analysis.helper;

public enum Dangerousness {
    NE(0), PE(1), E(2);

    private int dangerous;

    Dangerousness(int dangerousness) {
        this.dangerous = dangerousness;
    }

    public int getDangerous() {
        return dangerous;
    }

    public void setDangerous(int dangerous) {
        this.dangerous = dangerous;
    }

}
