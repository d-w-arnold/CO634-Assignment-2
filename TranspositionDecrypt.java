import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Decryption of ciphertext encoded with a Transposition Cipher.
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class TranspositionDecrypt extends Decrypt
{
    private String pt;

    public TranspositionDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
    }

    /**
     * Decrypt to plaintext written row-wise across a certain number of columns, the
     * ciphertext is formed by reading out successive columns from left to right.
     * @param smallestNumColumns The smallest number of columns.
     * @param largestNumColumns  The largest number of columns.
     */
    public String decrypt(int smallestNumColumns, int largestNumColumns)
    {
        System.out.println(getExercise(cipherFile) + ": Transposition Cipher");
        int ciphertextLen = ciphertext.length();
        ArrayList<String> potentialPts = new ArrayList<>();
        // For each column length
        for (int i = smallestNumColumns; i <= largestNumColumns; i++) {
            // Generate Columns
            String tmpCiphertext = ciphertext;
            int modAns = ciphertextLen % i; // 841 mod 4 = 1
            int baseColSize = (ciphertextLen - modAns) / i; // (841 - 1) / 4 = 210
            int incrementBaseColSize = baseColSize + 1;
            ArrayList<ArrayList<Character>> columns = new ArrayList<>();
            // Create each column as an ArrayList<Character>
            for (int j = 1; j <= i; j++) {
                if (j > modAns) { // 210
                    tmpCiphertext = genColumn(tmpCiphertext, columns, baseColSize);
                } else { // 211
                    tmpCiphertext = genColumn(tmpCiphertext, columns, incrementBaseColSize);
                }
            }
            // Generate potential plaintext from columns
            String potentialPt = "";
            for (int j = 0; j < baseColSize; j++) {
                for (int k = 0; k < columns.size(); k++) {
                    potentialPt += columns.get(k).get(j);
                }
            }
            for (int j = 0; j < modAns; j++) {
                potentialPt += columns.get(j).get(columns.get(j).size() - 1);
            }
            potentialPts.add(potentialPt);
        }
        // For each potential plaintext
        for (int i = 0; i < potentialPts.size(); i++) {
            String potentialPt = potentialPts.get(i);
            // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
            if (tess.contains(potentialPt)) {
                System.out.println("Decrypted: " + potentialPt);
                System.out.println("Number of Columns: " + (smallestNumColumns + i));
                System.out.println();
                pt = potentialPt;
            }
        }
        return pt;
    }

    private String genColumn(String tmpCiphertext, ArrayList<ArrayList<Character>> columns, int colSize)
    {
        String column = tmpCiphertext.substring(0, colSize);
        ArrayList<Character> colChars = new ArrayList<>();
        for (char c : column.toCharArray()) {
            colChars.add(c);
        }
        columns.add(colChars);
        tmpCiphertext = tmpCiphertext.substring(colSize);
        return tmpCiphertext;
    }
}
