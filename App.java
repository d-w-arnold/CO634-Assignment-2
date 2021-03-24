import java.io.*;
import java.nio.channels.FileChannel;

/**
 * App for Decryption of ciphertexts, using main() method.
 * Provides static outputFile() method to generate a TXT file with the decrypted plaintext of a given Cipher.
 * Any description included in these files is retained between consecutive runs of the main() method.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class App
{
    public static void main(String[] args) throws IOException
    {
        File tess26 = new File("." + File.separator + "tess26.txt");
        File tess27 = new File("." + File.separator + "tess27.txt");

        // Exercise 1
        File cexercise1 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise1.txt");
        CaesarDecrypt caesar = new CaesarDecrypt(tess26, cexercise1);
        outputFile(caesar.decrypt(), genPlaintextFileName(cexercise1));

        // Exercise 2
        File cexercise2 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise2.txt");
        VigDecrypt vig1 = new VigDecrypt(tess26, cexercise2);
        outputFile(vig1.decrypt("TESSOFTHEDURBERVILLES"), genPlaintextFileName(cexercise2));

        // Exercise 3
        File cexercise3 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise3.txt");
        VigDecrypt vig2 = new VigDecrypt(tess26, cexercise3);
        outputFile(vig2.decrypt(6), genPlaintextFileName(cexercise3));

        // Exercise 4
        File cexercise4 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise4.txt");
        VigDecrypt vig3 = new VigDecrypt(tess26, cexercise4);
        outputFile(vig3.decrypt(4, 6), genPlaintextFileName(cexercise4));

        // Exercise 5
        File cexercise5 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise5.txt");
        TranspositionDecrypt transpositionDecrypt1 = new TranspositionDecrypt(tess26, cexercise5);
        outputFile(transpositionDecrypt1.decrypt(4, 6), genPlaintextFileName(cexercise5));

        // Exercise 6
        File cexercise6 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise6.txt");
        TranspositionDecrypt transpositionDecrypt2 = new TranspositionDecrypt(tess26, cexercise6);
        outputFile(transpositionDecrypt2.decrypt(6), genPlaintextFileName(cexercise6));

        // Exercise 7
        File cexercise7 = new File("." + File.separator + "ciphertexts" + File.separator + "cexercise7.txt");
        GenSubDecrypt genSubDecrypt = new GenSubDecrypt(tess27, cexercise7);
        outputFile(genSubDecrypt.decrypt(), genPlaintextFileName(cexercise7));
    }

    private static void outputFile(String plaintext, String name) throws IOException
    {
        File outputDirectory = new File("." + File.separator + "outputs");
        String questionNumber = name.substring(name.length() - 5).substring(0, 1);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdir();
        }
        File outputFile = new File("." + File.separator + "outputs" + File.separator + name);
        if (outputFile.exists()) {
            File tmpFile = new File("." + File.separator + "outputs" + File.separator + "tmp.txt");
            copyFile(outputFile, tmpFile);
            outputFile.delete();
            BufferedWriter out = new BufferedWriter(new FileWriter(outputFile, true));
            out.write(plaintext.substring(0, 30) + "\n");
            out.write("\n" + "Full Decrypted Plaintext for Exercise " + questionNumber + ": " + plaintext + "\n");
            String currentLine;
            BufferedReader tmp = new BufferedReader(new FileReader(tmpFile));
            int index = 1;
            while ((currentLine = tmp.readLine()) != null) {
                if (index > 4) {
                    out.write("\n" + currentLine);
                }
                index++;
            }
            out.close();
            tmpFile.delete();
        } else {
            BufferedWriter out = new BufferedWriter(new FileWriter(outputFile, true));
            out.write(plaintext.substring(0, 30) + "\n");
            out.write("\n" + "Full Decrypted Plaintext for Exercise " + questionNumber + ": " + plaintext + "\n");
            out.close();
        }
    }

    private static void copyFile(File sourceFile, File destFile) throws IOException
    {
        if (!sourceFile.exists()) {
            return;
        }
        if (!destFile.exists()) {
            destFile.createNewFile();
        }
        FileChannel source;
        FileChannel destination;
        source = new FileInputStream(sourceFile).getChannel();
        destination = new FileOutputStream(destFile).getChannel();
        if (destination != null && source != null) {
            destination.transferFrom(source, 0, source.size());
        }
        if (source != null) {
            source.close();
        }
        if (destination != null) {
            destination.close();
        }
    }

    private static String genPlaintextFileName(File file)
    {
        return file.getName().substring(1);
    }
}
