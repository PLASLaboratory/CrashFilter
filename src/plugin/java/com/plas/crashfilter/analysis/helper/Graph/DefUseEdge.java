package plugin.java.com.plas.crashfilter.analysis.helper.Graph;


import java.util.ArrayList;
import java.util.List;

/**
 * Created by User on 2017-12-11.
 */
public class DefUseEdge {
    private DefUseNode source;
    private DefUseNode target;

    DefUseEdge(DefUseNode source, DefUseNode target) {
        this.source = source;
        this.target = target;
    }

    public DefUseNode getSource() {
        return source;
    }

    public DefUseNode getTarget() {
        return target;
    }

    public String toString() {
        return source + "->" + target + "\n";
    }

}
