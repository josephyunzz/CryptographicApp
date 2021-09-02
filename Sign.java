import java.io.Serializable;
import java.math.BigInteger;

public class Sign implements Serializable {

    private final byte[] h;
    private final BigInteger z;

    public Sign(byte[] h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    public byte[] getH() {
        return h;
    }

    public BigInteger getZ() {
        return z;
    }
}