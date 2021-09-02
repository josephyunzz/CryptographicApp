import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

public class CryptographicApp {
    private final Scanner userInput;

    public CryptographicApp() {
        userInput = new Scanner(System.in);
    }

    public static void main(String[] args) throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        new CryptographicApp().restart();
    }

    private void restart() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        System.out.println("\nChoose one of the options below:");
        System.out.println("\t1) Compute a cryptographic hash of a given file or input text.");
        System.out.println("\t2) Encrypt or decrypt a given file symmetrically under a passphrase.");
        System.out.println("\t3) Generate an elliptic key pair file from a passphrase.");
        System.out.println("\t4) Encrypt or decrypt a given file under an elliptic public key file.");
        System.out.println("\t5) Sign or verify a given file.");
        System.out.println("\t6) Quit.");
        promptUserChoice();
        enterUserChoice();
    }

    private static void promptUserChoice() {
        System.out.print("\nEnter a numbered option: ");
    }

    private static void promptUserPassword() {
        System.out.print("Enter a passphrase: ");
    }

    private void enterUserChoice() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        switch (userInput.nextLine()) {
            case "1":
                System.out.println("\nChoose one of the sub-options below:");
                System.out.println("\t1) Compute a cryptographic hash of a file.");
                System.out.println("\t2) Compute a cryptographic hash of an input text.");
                System.out.println("\t3) Go back.");
                promptUserChoice();
                enterHashOptions();
            case "2":
                System.out.println("\nChoose one of the sub-options below:");
                System.out.println("\t1) Encrypt a file symmetrically under a given passphrase.");
                System.out.println("\t2) Decrypt a symmetric cryptogram under a given passphrase.");
                System.out.println("\t3) Go Back.");
                promptUserChoice();
                enterSymmetricOptions();
            case "3":
                promptUserPassword();
                EllipticCurveCryptography.generateKeyPair(userInput.nextLine());
                restart();
            case "4":
                System.out.println("\nChoose one of the sub-options below:");
                System.out.println("\t1) Encrypt a data file with a public key file.");
                System.out.println("\t2) Decrypt a .ECC file with a passphrase.");
                System.out.println("\t3) Go Back.");
                promptUserChoice();
                enterECCOptions();
            case "5":
                System.out.println("\nChoose one of the sub-options below:");
                System.out.println("\t1) Sign a given file under a passphrase and write the signature to a file.");
                System.out.println("\t2) Verify a given file and its signature file under a public key file.");
                System.out.println("\t3) Go Back.");
                promptUserChoice();
                enterSignatureOptions();
            case "6":
                System.exit(0);
            default:
                promptUserChoice();
                enterUserChoice();
        }
    }

    private void enterHashOptions() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        switch (userInput.nextLine()) {
            case "1":
                System.out.println("Waiting for file selection...");
                FileDialog fd = new FileDialog(new JFrame(), "Select a file to hash: ", FileDialog.LOAD);
                fd.setVisible(true);

                if (fd.getFile() != null) {
                    System.out.println("The file \"" + fd.getFile() + "\" has been hashed: " +
                            KMACXOF256.convertBytesToHex(SHA3.KMACXOF256("".getBytes(),
                                    (new String(Files.readAllBytes(Paths.get(fd.getDirectory() +
                                            fd.getFile())))).getBytes(), 512, "D".getBytes())));
                } else {
                    System.out.println("\nInvalid file.");
                }

                restart();
            case "2":
                System.out.print("Enter the string to hash: ");
                String string = userInput.nextLine();
                System.out.println("The text \"" + string + "\" has been hashed: " +
                        KMACXOF256.convertBytesToHex(SHA3.KMACXOF256("".getBytes(),
                                string.getBytes(), 512, "D".getBytes())));
                restart();
            case "3":
                restart();
            default:
                promptUserChoice();
                enterHashOptions();
        }
    }

    private void enterSymmetricOptions() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        switch (userInput.nextLine()) {
            case "1":
                promptUserPassword();
                String passphrase = userInput.nextLine();

                System.out.println("Waiting for file selection...");

                FileDialog fd = new FileDialog(new JFrame(), "Select a file to encrypt", FileDialog.LOAD);
                fd.setVisible(true);

                if (fd.getFile() != null) {
                    KMACXOF256.encrypt(fd, passphrase);
                } else {
                    System.out.println("\nInvalid file.");
                }
                restart();
            case "2":
                promptUserPassword();
                passphrase = userInput.nextLine();

                System.out.println("Waiting for file selection...");

                fd = new FileDialog(new JFrame(), "Select a .cryptogram file to decrypt", FileDialog.LOAD);
                fd.setVisible(true);

                if (fd.getFile() != null && fd.getFile().endsWith(".cryptogram")) {
                    KMACXOF256.decrypt(fd, passphrase);
                } else {
                    System.out.println("\nInvalid file.");
                }
                restart();
            case "3":
                restart();
            default:
                promptUserChoice();
                enterSymmetricOptions();
        }
    }

    private void enterSignatureOptions() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        switch (userInput.nextLine()) {
            case "1":
                promptUserPassword();
                String passphrase = userInput.nextLine();

                JFileChooser jfc = new JFileChooser(System.getProperty("user.dir"));
                System.out.println("Waiting for file selection...");

                if (jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                    Signature.generateSignature(passphrase, jfc);
                } else {
                    System.out.println("Canceled operation.");
                }
                restart();
            case "2":
                JFileChooser pk_jfc = new JFileChooser(System.getProperty("user.dir"));
                JFileChooser file_jfc = new JFileChooser(System.getProperty("user.dir"));
                JFileChooser signature_jfc = new JFileChooser(System.getProperty("user.dir"));
                System.out.println("Waiting for public key file selection...");

                if (pk_jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                    System.out.println("Waiting for file selection...");
                    if (file_jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                        System.out.println("Waiting for signature file selection...");
                        if (signature_jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                            Signature.verifySignature(pk_jfc, file_jfc, signature_jfc);
                        } else {
                            System.out.println("Canceled operation.");
                        }
                    } else {
                        System.out.println("Canceled operation.");
                    }
                } else {
                    System.out.println("Canceled operation.");
                }
                restart();
            case "3":
                restart();
            default:
                promptUserChoice();
                enterSignatureOptions();
        }
    }

    private void enterECCOptions() throws IOException, InvocationTargetException,
            InterruptedException, ClassNotFoundException {
        switch (userInput.nextLine()) {
            case "1":
                JFileChooser pk_jfc = new JFileChooser(System.getProperty("user.dir"));
                JFileChooser file_jfc = new JFileChooser(System.getProperty("user.dir"));

                System.out.println("Waiting for public key file selection...");
                if (pk_jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                    System.out.println("Waiting for data file selection...");
                    if (file_jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                        EllipticCurveCryptography.encrypt(pk_jfc, file_jfc);
                    } else {
                        System.out.println("Canceled operation.");
                    }
                } else {
                    System.out.println("Canceled operation.");
                }
                restart();
            case "2":
                promptUserPassword();
                String passphrase = userInput.nextLine();

                JFileChooser jfc = new JFileChooser(System.getProperty("user.dir"));

                System.out.println("Waiting for .ECC file selection...");
                if (jfc.showOpenDialog(null) != JFileChooser.CANCEL_OPTION) {
                    if (jfc.getSelectedFile().toString().endsWith(".ECC")) {
                        EllipticCurveCryptography.decrypt(passphrase, jfc);
                    } else {
                        System.out.println("Invalid file.");
                    }
                } else {
                    System.out.println("Canceled operation.");
                }
                restart();
            case "3":
                restart();
            default:
                promptUserChoice();
                enterECCOptions();
        }
    }
}
