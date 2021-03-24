import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Decryption of ciphertext encoded with a Caesar Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class CaesarDecrypt extends Decrypt
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
    private final HashMap<Character, Integer> occurrences;
    private final HashMap<Character, String> decryptedPlaintexts;
    private String pt;

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
            StringBuilder plaintext = new StringBuilder();
            // For every single character in the ciphertext.
            for (int j = 0; j < ciphertext.length(); j++) {
                int c = findIndex(charAlphabet, ciphertext.charAt(j));
                plaintext.append(charAlphabet[(charAlphaLen + (c - i)) % charAlphaLen]);
            }
            occurrences.put(charAlphabet[i], getTotalOccurrences(plaintext.toString(), ENGLISH_COMMON_PAIRS_AND_REPEATS));
            decryptedPlaintexts.put(charAlphabet[i], plaintext.toString());
        }
        char maximumOccurrencesKey = Objects.requireNonNull(occurrences.entrySet().stream().max(Map.Entry.comparingByValue()).orElse(null)).getKey();
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
