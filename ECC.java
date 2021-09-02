import java.io.Serializable;
import java.util.Arrays;

public class ECC implements Serializable {

    private final EllipticCurvePoint z;
    private final byte[] c;
    private final byte[] t;

    public ECC(EllipticCurvePoint z, byte[] c, byte[] t) {
        this.z = z;
        this.c = c;
        this.t = t;
    }

    public EllipticCurvePoint getZ() {
        return z;
    }

    public byte[] getC() {
        return c;
    }

    public byte[] getT() {
        return t;
    }

    @Override
    public String toString() {
        return "Z: " + z.getX() + " C: " + Arrays.toString(c) + "T: " + Arrays.toString(t);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }
}
