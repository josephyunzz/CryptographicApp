import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class KMACXOF256 {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private KMACXOF256() {}

    public static void encrypt(FileDialog dialog, String passphrase) throws IOException {
        byte[] message = Files.readAllBytes(Paths.get(dialog.getDirectory() + dialog.getFile()));
        byte[] pw = (passphrase != null && passphrase.length() > 0) ? passphrase.getBytes() : new byte[0];
        new FileOutputStream(dialog.getDirectory() + dialog.getFile() + ".cryptogram")
                .write(getOutput(message, pw));
        System.out.println("Encryption successful. " + dialog.getFile() +
                " has been encrypted to: " + convertBytesToHex(message));
    }

    private static byte[] concatByteArray(byte[] arr1, byte[] arr2) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(arr1);
        baos.write(arr2);
        return baos.toByteArray();
    }

    private static byte[] getOutput(byte[] message, byte[] pw) throws IOException {
        byte[] z = new byte[64];
        new SecureRandom().nextBytes(z);
        byte[] sk = SHA3.KMACXOF256(concatByteArray(z, pw), "".getBytes(), 1024, "S".getBytes());
        byte[] ir = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 0, 64),
                "".getBytes(), 8 * message.length, "SKE".getBytes());
        byte[] c = new byte[message.length];
        int i = 0;
        while (i < message.length) {
            c[i] = (byte) (ir[i] ^ message[i]);
            i++;
        }
        byte[] t = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 64, 128), message, 512, "SKA".getBytes());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(z);
        baos.write(c);
        baos.write(t);
        return baos.toByteArray();
    }

    public static void decrypt(FileDialog fd, String passphrase) throws IOException {
        DecryptedOutput result = getMessage(Files.readAllBytes(Paths.get(fd.getDirectory() + fd.getFile())),
                (passphrase != null && passphrase.length() > 0) ? passphrase.getBytes() : new byte[0]);
        if (result.TMatches) {
            System.out.println("Decryption successful. "  + fd.getFile() +
                    " has been decrypted to: " + convertBytesToHex(result.m));
        } else {
            System.out.println("Decryption unsuccessful: Incorrect passphrase.");
        }
    }


    private static DecryptedOutput getMessage(byte[] cryptogram, byte[] pw) throws IOException {
        byte[] sk = SHA3.KMACXOF256(concatByteArray(Arrays.copyOfRange(cryptogram, 0, 64), pw), "".getBytes(), 1024, "S".getBytes());
        byte[] c = Arrays.copyOfRange(cryptogram,64, cryptogram.length - 64);
        byte[] ir = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 0, 64),
                "".getBytes(), c.length * 8, "SKE".getBytes());
        byte[] m = new byte[c.length];
        int i = 0;
        while (i < c.length) {
            m[i] = (byte) (c[i] ^ ir[i]);
            i++;
        }
        byte[] tp = SHA3.KMACXOF256(Arrays.copyOfRange(sk, 64, 128), m, 512, "SKA".getBytes());
        return new DecryptedOutput(m, Arrays.equals(Arrays.copyOfRange
                (cryptogram, cryptogram.length - 64, cryptogram.length), tp));
    }

    public static String convertBytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        int i = 0;
        while (i < bytes.length) {
            int v = bytes[i] & 0xFF;
            hex.append(HEX_ARRAY[v >>> 4]);
            hex.append(HEX_ARRAY[v & 0x0F]);
            i++;
        }
        return hex.toString();
    }

    private static class DecryptedOutput {
        byte[] m;
        boolean TMatches;
        DecryptedOutput(byte[] m, boolean TMatches) {
            this.m = m;
            this.TMatches = TMatches;
        }
    }
}
