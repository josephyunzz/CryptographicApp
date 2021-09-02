import java.io.Serializable;
import java.math.BigInteger;

public class EllipticCurvePoint implements Serializable {

    public static final BigInteger MERSENNE_PRIME = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    public static final Integer D = -376014;

    private final BigInteger x;
    private final BigInteger y;

    public EllipticCurvePoint(BigInteger x, BigInteger y) {
        this.x = x.mod(MERSENNE_PRIME);
        this.y = y.mod(MERSENNE_PRIME);
    }

    public EllipticCurvePoint(BigInteger x, boolean lsb) {
        this.x = x;
        this.y = sqrt(BigInteger.ONE.subtract(x.modPow(new BigInteger("2"), MERSENNE_PRIME)).
                        multiply(BigInteger.ONE.add(BigInteger.valueOf(D * -1).
                        multiply(x.modPow(new BigInteger("2"), MERSENNE_PRIME)).
                        mod(MERSENNE_PRIME)).modInverse(MERSENNE_PRIME)), MERSENNE_PRIME, lsb);
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public static EllipticCurvePoint getBasePoint() {
        return new EllipticCurvePoint(BigInteger.valueOf(18), false);
    }

    public static EllipticCurvePoint selfMultiply (BigInteger s, EllipticCurvePoint base) {
        EllipticCurvePoint toSend = base;
        int i = s.toString(2).length() - 1;
        while (i >= 0) {
            toSend = toSend.summation(toSend);
            if (s.toString(2).charAt(i) == '1') {
                toSend = toSend.summation(base);
            }
            i--;
        }
        return toSend;
    }

    /**
     * Taken from "Appendix: computing square roots modulo p" in the spec.
     */
    private static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public EllipticCurvePoint summation(EllipticCurvePoint other) {
        final BigInteger multiply = BigInteger.valueOf(D)
                .multiply(x).multiply(y).multiply(other.x).multiply(other.y);
        return new EllipticCurvePoint(x.multiply(other.y).add(y.multiply(other.x)).multiply
                (BigInteger.ONE.add(multiply).modInverse(MERSENNE_PRIME)).mod(MERSENNE_PRIME),
                y.multiply(other.y).subtract(x.multiply(other.x)).multiply
                        (BigInteger.ONE.subtract(multiply).modInverse(MERSENNE_PRIME)).mod(MERSENNE_PRIME));
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof EllipticCurvePoint)) {
            return false;
        }
        EllipticCurvePoint other = (EllipticCurvePoint) obj;
        return x.equals(other.x) && y.equals(other.y);
    }
}