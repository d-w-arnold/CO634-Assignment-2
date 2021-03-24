import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Abstract Class for Decryption of ciphertext encoded with a Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public abstract class Decrypt
{
    protected String tess;
    protected String ciphertext;
    protected File cipherFile;
    protected char[] charAlphabet;

    public Decrypt(File tessFile, File cipherFile) throws IOException
    {

        tess = new BufferedReader(new FileReader(tessFile)).readLine();
        ciphertext = new BufferedReader(new FileReader(cipherFile)).readLine();
        this.cipherFile = cipherFile;
        setCharAlphabet(tessFile);
    }

    protected int findIndex(char[] arr, int t)
    {
        if (arr == null) {
            return -1;
        }
        int len = arr.length;
        int i = 0;
        while (i < len) {
            if (arr[i] == t) {
                return i;
            }
            i++;
        }
        return -1;
    }

    protected String getExercise(File file)
    {
        String cipherFileName = file.getName();
        return cipherFileName.substring(1, cipherFileName.length() - 4);
    }

    protected int getTotalOccurrences(String plaintext, ArrayList<String> english_common_pairs_and_repeats)
    {
        int totalOccurrences = 0;
        totalOccurrences = getTotalOccurrencesHelper(plaintext, totalOccurrences, english_common_pairs_and_repeats);
        return totalOccurrences;
    }

    protected int getTotalOccurrencesHelper(String newTmpPT, int totalOccurrences, ArrayList<String> english_trigraphs)
    {
        for (String trigraph : english_trigraphs) {
            int lastIndex = 0;
            while (lastIndex != -1) {
                lastIndex = newTmpPT.indexOf(trigraph, lastIndex);
                if (lastIndex != -1) {
                    totalOccurrences++;
                    lastIndex += trigraph.length();
                }
            }
        }
        return totalOccurrences;
    }

    private void setCharAlphabet(File tess)
    {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (tess.getName().equals("tess26.txt")) {
            charAlphabet = alphabet.toCharArray();
        } else if (tess.getName().equals("tess27.txt")) {
            charAlphabet = (alphabet + "|").toCharArray();
        } else {
            charAlphabet = alphabet.toCharArray();
        }
    }
}
