import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Decryption of ciphertext encoded with a Transposition Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class TranspositionDecrypt extends Decrypt
{
    final private ArrayList<String> ENGLISH_COMMON_PAIRS_AND_REPEATS = new ArrayList<>()
    {{
        add("TH");
        add("ER");
        add("ON");
        add("AN");
        add("SS");
        add("EE");
        add("TT");
        add("FF");
    }};
    private final ArrayList<String> columnCombinations;
    private String pt;

    public TranspositionDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.columnCombinations = new ArrayList<>();
    }

    /**
     * Decrypt to plaintext written row-wise across a certain number of columns, the
     * ciphertext is formed by reading out successive columns from left to right.
     *
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
            StringBuilder potentialPt = new StringBuilder();
            for (int j = 0; j < baseColSize; j++) {
                for (ArrayList<Character> column : columns) {
                    potentialPt.append(column.get(j));
                }
            }
            for (int j = 0; j < modAns; j++) {
                potentialPt.append(columns.get(j).get(columns.get(j).size() - 1));
            }
            potentialPts.add(potentialPt.toString());
        }
        // For each potential plaintext, count the number of common pair and repeats
        LinkedHashMap<String, Integer> occurrences = new LinkedHashMap<>();
        for (String potentialPt : potentialPts) {
            occurrences.put(potentialPt, getTotalOccurrences(potentialPt, ENGLISH_COMMON_PAIRS_AND_REPEATS));
        }
        // The plaintext with th maximum number of common pair and repeat occurrences
        String plaintextMaxOccurrences = Objects.requireNonNull(occurrences.entrySet().stream().max(Map.Entry.comparingByValue()).orElse(null)).getKey();
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(plaintextMaxOccurrences)) {
            System.out.println("Decrypted: " + plaintextMaxOccurrences);
            System.out.println("Number of Columns: " + (smallestNumColumns + potentialPts.indexOf(plaintextMaxOccurrences)));
            System.out.println();
            pt = plaintextMaxOccurrences;
        }
        return pt;
    }

    /**
     * Decrypt to plaintext written row-wise across a certain number of columns, the
     * ciphertext is formed by reading out successive columns from left to right.
     *
     * @param numColumns The smallest number of columns.
     */
    public String decrypt(int numColumns)
    {
        System.out.println(getExercise(cipherFile) + ": Transposition Cipher");
        int ciphertextLen = ciphertext.length();
        // Generate Columns
        String tmpCiphertext = ciphertext;
        int modAns = ciphertextLen % numColumns; // 841 mod 4 = 1
        int baseColSize = (ciphertextLen - modAns) / numColumns; // (841 - 1) / 4 = 210
        ArrayList<ArrayList<Character>> columns = new ArrayList<>();
        // Create each column as an ArrayList<Character>
        for (int j = 1; j <= numColumns; j++) {
            tmpCiphertext = genColumn(tmpCiphertext, columns, baseColSize);
        }
        // Find sequence of columns for which the highest number of pairAndRepeatOccurences happen
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < columns.size(); i++) {
            s.append(i);
        }
        genColumnCombinations(s.toString(), 0, (s.length() - 1));
        // Key is the ordering of columns: e.g. 514203
        // Value is the plaintext created from the certain ordering of columns
        HashMap<String, String> plaintextForColumnCombinations = new HashMap<>();
        // For each combination of columns 012345, decrypt to plaintext
        for (String colComb : columnCombinations) {
            ArrayList<Integer> cList = new ArrayList<>();
            for (char c : colComb.toCharArray()) {
                cList.add(Character.getNumericValue(c));
            }
            // Generate potential plaintext from column combination
            StringBuilder potentialPt = new StringBuilder();
            for (int j = 0; j < baseColSize; j++) {
                for (int c : cList) {
                    potentialPt.append(columns.get(c).get(j));
                }
            }
            plaintextForColumnCombinations.put(colComb, potentialPt.toString());
        }
        // Key is the ordering of columns: e.g. 514203
        // Value is the number of pairAndRepeatOccurences for a plaintext
        //  created from the certain ordering of columns
        HashMap<String, Integer> pairAndRepeatOccurences = new HashMap<>();
        // For each combination of columns 012345
        // Count pairAndRepeatOccurences for each column combination plaintext
        for (String colComb : columnCombinations) {
            String input = plaintextForColumnCombinations.get(colComb);
            int totalOccurrences = 0;
            for (String pair : ENGLISH_COMMON_PAIRS_AND_REPEATS) {
                int index = input.indexOf(pair);
                int occurrences = 0;
                while (index != -1) {
                    occurrences++;
                    input = input.substring(index + 1);
                    index = input.indexOf(pair);
                }
                totalOccurrences += occurrences;
            }
            pairAndRepeatOccurences.put(colComb, totalOccurrences);
        }
        // The highest count would be the column ordering to most likely yield the correct decryption
        String key = Collections.max(pairAndRepeatOccurences.entrySet(), Comparator.comparingInt(Map.Entry::getValue)).getKey();
        String potentialPt = plaintextForColumnCombinations.get(key);
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(potentialPt)) {
            System.out.println("Decrypted: " + potentialPt);
            System.out.println("Number of Columns: " + numColumns);
            System.out.println();
            pt = potentialPt;
        }
        return pt;
    }

    // Generate a column
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

    // Generate column combinations
    private void genColumnCombinations(String str, int l, int r)
    {
        if (l == r) {
            columnCombinations.add(str);
        } else {
            for (int i = l; i <= r; i++) {
                str = swap(str, l, i);
                genColumnCombinations(str, l + 1, r);
                str = swap(str, l, i);
            }
        }
    }

    // Helper method for genColumnCombinations()
    private String swap(String a, int i, int j)
    {
        char temp;
        char[] charArray = a.toCharArray();
        temp = charArray[i];
        charArray[i] = charArray[j];
        charArray[j] = temp;
        return String.valueOf(charArray);
    }
}
