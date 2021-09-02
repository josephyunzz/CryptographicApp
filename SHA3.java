import java.util.Arrays;

/**
 * @author Markku-Juhani Saarinen (original implementation in C)
 */
public class SHA3 {
    private static final byte[] KMAC_N = {(byte)0x4B, (byte)0x4D, (byte)0x41, (byte)0x43};
    private static final byte[] right_encode_0 = {(byte)0x00, (byte)0x01};
    private static final int KECCAKF_ROUNDS = 24;
    private final byte[] b = new byte[200];
    private boolean ext = false;
    private boolean kmac = false;
    private int pt;
    private int rsiz;

    private static final long[] keccakf_rndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] keccakf_rotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[] keccakf_piln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    private static long ROTL64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    private static void sha3_keccakf(byte[] v) {
        long[] q = new long[25];
        long[] bc = new long[5];

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            q[i] =  (((long)v[j] & 0xFFL)      ) | (((long)v[j + 1] & 0xFFL) <<  8) |
                    (((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
                    (((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
                    (((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
        }

        // actual iteration
        for (int r = 0; r < KECCAKF_ROUNDS; r++) {

            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    q[j + i] ^= t;
                }
            }

            // Rho Pi
            long t = q[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = q[j];
                q[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }

            //  Chi
            for (int j = 0; j < 25; j += 5) {
                System.arraycopy(q, j, bc, 0, 5);
                for (int i = 0; i < 5; i++) {
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            //  Iota
            q[0] ^= keccakf_rndc[r];
        }

        // endianess conversion. this is redundant on little-endian targets
        for (int i = 0, j = 0; i < 25; i++, j += 8) {
            long t = q[i];
            v[j] = (byte)((t      ) & 0xFF);
            v[j + 1] = (byte)((t >>  8) & 0xFF);
            v[j + 2] = (byte)((t >> 16) & 0xFF);
            v[j + 3] = (byte)((t >> 24) & 0xFF);
            v[j + 4] = (byte)((t >> 32) & 0xFF);
            v[j + 5] = (byte)((t >> 40) & 0xFF);
            v[j + 6] = (byte)((t >> 48) & 0xFF);
            v[j + 7] = (byte)((t >> 56) & 0xFF);
        }
    }

    public SHA3() {}

    private static final byte[] left_encode_0 = {(byte)0x01, (byte)0x00};

    private static byte[] concat(byte[] a, byte[] b) {
        int al;
        int bl;
        if (a != null) {
            al = a.length;
        } else {
            al = 0;
        }
        if (b != null) {
            bl = b.length;
        } else {
            bl = 0;
        }
        byte[] c = new byte[al + bl];
        System.arraycopy(a, 0, c, 0, al);
        System.arraycopy(b, 0, c, al, bl);
        return c;
    }

    private static byte[] encode_string(byte[] S) {
        int sl;
        byte[] ls;
        if (S != null) {
            sl = S.length;
        } else {
            sl = 0;
        }
        if (S != null) {
            ls = left_encode(sl << 3);
        } else {
            ls = left_encode_0;
        }
        byte[] encS = new byte[ls.length + sl];
        System.arraycopy(ls, 0, encS, 0, ls.length);
        if (S != null) {
            System.arraycopy(S, 0, encS, ls.length, sl);
        } else {
            System.arraycopy(encS, 0, encS, ls.length, sl);
        }
        return encS;
    }

    private static byte[] left_encode(int x) {
        int n = 1;
        while ((1 << (8*n)) <= x) {
            n++;
        }
        if (n >= 256) {
            throw new RuntimeException();
        }
        byte[] val = new byte[n + 1];

        int i = n;
        while (i > 0) {
            val[i] = (byte)(x & 0xFF);
            x >>>= 8;
            i--;
        }
        val[0] = (byte)n;
        return val;
    }

    private static byte[] bytepad(byte[] X) {
        byte[] wenc = left_encode(136);
        byte[] z = new byte[136 *((wenc.length + X.length + 136 - 1)/ 136)];
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        int i = wenc.length + X.length;
        while (i < z.length) {
            z[i] = (byte)0;
            i++;
        }
        return z;
    }

    public void init256() {
        Arrays.fill(this.b, (byte)0);
        this.rsiz = 136;
        this.pt = 0;
        this.ext = false;
        this.kmac = false;
    }

    public void cinit256(byte[] N, byte[] S) {
        init256();
        if ((N != null && N.length != 0) || (S != null && S.length != 0)) {
            this.ext = true;
            byte[] prefix = bytepad(concat(encode_string(N), encode_string(S)));
            update(prefix, prefix.length);
        }
    }

    public void kinit256(byte[] K, byte[] S) {
        byte[] encK = bytepad(encode_string(K));
        cinit256(KMAC_N, S);
        this.kmac = true;
        update(encK, encK.length);
    }

    public void update(byte[] data, int len) {
        int j = this.pt;
        int i = 0;
        while (i < len) {
            this.b[j++] ^= data[i];
            if (j >= this.rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            i++;
        }
        this.pt = j;
    }

    public void xof() {
        if (kmac) {
            update(right_encode_0, right_encode_0.length);
        }
        if (this.ext) {
            this.b[this.pt] = (byte) (this.b[this.pt] ^ (byte) 0x04);
        } else {
            this.b[this.pt] = (byte) (this.b[this.pt] ^ (byte) 0x1F);
        }
        this.b[this.rsiz - 1] = (byte) (this.b[this.rsiz - 1] ^ (byte) 0x80);
        sha3_keccakf(b);
        this.pt = 0;
    }

    public void out(byte[] out, int len) {
        int j = pt;
        int i = 0;
        while (i < len) {
            if (j >= rsiz) {
                sha3_keccakf(b);
                j = 0;
            }
            out[i] = b[j++];
            i++;
        }
        pt = j;
    }

    public static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        if ((L & 7) != 0) {
            throw new RuntimeException();
        }
        byte[] val = new byte[L >>> 3];
        SHA3 sha3 = new SHA3();
        sha3.kinit256(K, S);
        sha3.update(X, X.length);
        sha3.xof();
        sha3.out(val, L >>> 3);
        return val;
    }

}

