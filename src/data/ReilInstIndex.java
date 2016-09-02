package data;

public enum ReilInstIndex {
    ADD(1), AND(2), BISZ(3), BSH(4), DIV(5), JCC(6), LDM(7), MOD(8), MUL(9), NOP(10), OR(11), STM(12), STR(13), SUB(
            14), UNDEF(15), UNKNOWN(16), XOR(17), OTHERS(18);
    private final int index;

    private ReilInstIndex(int index) {
        this.index = index;
    }

    public int getIndex() {
        return this.index;
    }
}
