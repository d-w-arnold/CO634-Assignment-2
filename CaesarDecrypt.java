import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

/**
 * Decryption of ciphertext encoded with a Caesar Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class CaesarDecrypt extends Decrypt
{
    final private ArrayList<String> ENGLISH_COMMON_PAIRS_AND_REPEATS = new ArrayList<String>()
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
    private String pt;
    private HashMap<Character, Integer> occurrences;
    private HashMap<Character, String> decryptedPlaintexts;

    public CaesarDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.occurrences = new HashMap<>();
        this.decryptedPlaintexts = new HashMap<>();
    }

    public String decrypt()
    {
        int charAlphaLen = charAlphabet.length;
        // For all possible characters in the character alphabet.
        for (int i = 0; i < charAlphaLen; i++) {
            String plaintext = "";
            // For every single character in the ciphertext.
            for (int j = 0; j < ciphertext.length(); j++) {
                int c = findIndex(charAlphabet, ciphertext.charAt(j));
                plaintext += charAlphabet[(charAlphaLen + (c - i)) % charAlphaLen];
            }
            System.out.println();
            int totalOccurrences = 0;
            for (String commonPairOrRepeat : ENGLISH_COMMON_PAIRS_AND_REPEATS) {
                int lastIndex = 0;
                while (lastIndex != -1) {
                    lastIndex = plaintext.indexOf(commonPairOrRepeat, lastIndex);
                    if (lastIndex != -1) {
                        totalOccurrences++;
                        lastIndex += commonPairOrRepeat.length();
                    }
                }
            }
            occurrences.put(charAlphabet[i], totalOccurrences);
            decryptedPlaintexts.put(charAlphabet[i], plaintext);
        }
        char maximumOccurrencesKey = occurrences.entrySet().stream().max(Comparator.comparing(Map.Entry::getValue)).get().getKey();
        String potentialPlaintext = decryptedPlaintexts.get(maximumOccurrencesKey);
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(potentialPlaintext)) {
            System.out.println(getExercise(cipherFile) + ": Caesar Cipher");
            System.out.println("Decrypted: " + potentialPlaintext);
            System.out.println("Key: " + maximumOccurrencesKey);
            System.out.println();
            pt = potentialPlaintext;
        }
        return pt;
    }
}
