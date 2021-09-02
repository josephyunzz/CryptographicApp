import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class EllipticCurveCryptography {
    public static void generateKeyPair(String passphrase) throws InvocationTargetException,
            InterruptedException, IOException {
        BigInteger bi = BigInteger.valueOf(4).multiply
                (new BigInteger(SHA3.KMACXOF256(passphrase.getBytes(), "".getBytes(), 512, "K".getBytes())));
        EllipticCurvePoint ecp = EllipticCurvePoint.selfMultiply(bi, EllipticCurvePoint.getBasePoint());

        final JFileChooser jfc = new JFileChooser(System.getProperty("user.dir"));
        System.out.println("Waiting for user to specify output directory...");

        jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            EventQueue.invokeAndWait(() -> jfc.showOpenDialog(null));
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(jfc.getSelectedFile().toString()
                    + "/public_key_file_password=" + passphrase));
            oos.writeObject(ecp);
            oos.close();
            System.out.println("Private Key: " + bi.toString());
            System.out.println("Public Key X: " + ecp.getX().toString());
            System.out.println("Public Key Y: " + ecp.getY().toString());
            System.out.println("\nThe public key file has been saved to: "
                    + jfc.getSelectedFile().toString() + "\\pk_passphrase=" + passphrase);
    }

    public static void encrypt(JFileChooser pk_jfc, JFileChooser file_jfc) throws IOException, ClassNotFoundException {
        byte[] efc = Files.readAllBytes(Paths.get(file_jfc.getSelectedFile().toString()));
        byte[] z = new byte[64];
        new SecureRandom().nextBytes(z);
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(z));
        EllipticCurvePoint ecp = EllipticCurvePoint.selfMultiply(k, (EllipticCurvePoint) new ObjectInputStream
                (new FileInputStream(pk_jfc.getSelectedFile().toString())).readObject());
        EllipticCurvePoint ecp2 = EllipticCurvePoint.selfMultiply(k, EllipticCurvePoint.getBasePoint());
        byte[] sk = SHA3.KMACXOF256(ecp.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
        byte[] ir = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 0, 64), "".getBytes(),
                efc.length * 8, "PKE".getBytes());
        byte[] c = new byte[efc.length];

        int i = 0;
        while (i < efc.length) {
            c[i] = (byte) (efc[i] ^ ir[i]);
            i++;
        }

        byte[] t = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 64, 128),
                efc, 512, "PKA".getBytes());
            ObjectOutputStream oos = new ObjectOutputStream
                    (new FileOutputStream(file_jfc.getSelectedFile() + ".ECC"));
            oos.writeObject(new ECC(ecp2, c, t));
            oos.close();
        System.out.println("Encryption successful: " + bytesToHex(efc));
    }

    public static void decrypt(String password, JFileChooser jfc) throws IOException, ClassNotFoundException {
        ECC rc = (ECC) new ObjectInputStream
                (new FileInputStream(jfc.getSelectedFile().toString())).readObject();
        byte[] C = rc.getC();
        byte[] T = rc.getT();
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger
                (SHA3.KMACXOF256(password.getBytes(), "".getBytes(), 512, "K".getBytes())));
        EllipticCurvePoint ecp = EllipticCurvePoint.selfMultiply(s, rc.getZ());

        byte[] sk = SHA3.KMACXOF256(ecp.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
        byte[] mp = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 0, 64),
                "".getBytes(), C.length * 8, "PKE".getBytes());
        byte[] m = new byte[C.length];

        int i = 0;
        while (i < m.length) {
            m[i] = (byte) (mp[i] ^ C[i]);
            i++;
        }
        byte[] tp = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 64, 128), m, 512, "PKA".getBytes());

        if (Arrays.equals(tp, T)) {
            System.out.println("Decryption successful: " + (bytesToHex(m)));
        } else {
            System.out.println("Decryption unsuccessful: Incorrect passphrase.");
        }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexCharacters = new char[bytes.length * 2];
        int j = 0;
        while (j < bytes.length) {
            int v = bytes[j] & 0xFF;
            hexCharacters[j * 2] = hexArray[v >>> 4];
            hexCharacters[j * 2 + 1] = hexArray[v & 0x0F];
            j++;
        }
        return new String(hexCharacters);
    }
}
