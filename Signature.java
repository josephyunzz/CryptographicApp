import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Signature {

    private Signature() {}

    public static void generateSignature(String password, JFileChooser fileChooser) throws IOException {
        byte[] m =  Files.readAllBytes(Paths.get(fileChooser.getSelectedFile().toString()));
        BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger
                (SHA3.KMACXOF256(password.getBytes(), "".getBytes(), 512, "K".getBytes())));
        BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger
                (SHA3.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes())));
        byte[] h = SHA3.KMACXOF256(EllipticCurvePoint.selfMultiply
                (k, EllipticCurvePoint.getBasePoint()).getX().toByteArray(), m, 512, "T".getBytes());
        BigInteger z = (k.subtract(new BigInteger(h).multiply(s))).mod(new BigInteger("2").pow(519).subtract
                (new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765")));
        ObjectOutputStream oos = new ObjectOutputStream
                (new FileOutputStream(fileChooser.getSelectedFile() + ".Signature"));
        oos.writeObject(new Sign(h, z));
        oos.close();

        System.out.println("Signature file successfully generated.");
    }

    public static void verifySignature(JFileChooser pk_jfc, JFileChooser file_jfc, JFileChooser signature_jfc)
            throws IOException, ClassNotFoundException {
        EllipticCurvePoint rc = (EllipticCurvePoint) new ObjectInputStream
                (new FileInputStream(pk_jfc.getSelectedFile().toString())).readObject();
        Sign rs = (Sign) new ObjectInputStream
                (new FileInputStream(signature_jfc.getSelectedFile().toString())).readObject();
        byte[] m = Files.readAllBytes(Paths.get(file_jfc.getSelectedFile().toString()));
        byte[] t = SHA3.KMACXOF256(EllipticCurvePoint.selfMultiply(rs.getZ(),
                EllipticCurvePoint.getBasePoint()).summation(EllipticCurvePoint.selfMultiply
                (new BigInteger(rs.getH()), rc)).getX().toByteArray(), m, 512, "T".getBytes());
        System.out.println(Arrays.equals(t, rs.getH()) ? "Signature is legitimate." : "Signature is illegitimate.");
    }
}
