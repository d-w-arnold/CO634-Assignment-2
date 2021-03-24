import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Decryption of ciphertext encoded with a Vigenere Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class VigDecrypt extends Decrypt
{
    final private LinkedHashMap<Character, Double> FREQUENCY_OF_LETTERS_IN_ENGLISH = new LinkedHashMap<>()
    {{
        put('A', 8.167);
        put('B', 1.492);
        put('C', 2.782);
        put('D', 4.253);
        put('E', 12.702);
        put('F', 2.228);
        put('G', 2.015);
        put('H', 6.094);
        put('I', 6.996);
        put('J', 0.153);
        put('K', 0.772);
        put('L', 4.025);
        put('M', 2.406);
        put('N', 6.749);
        put('O', 7.507);
        put('P', 1.929);
        put('Q', 0.095);
        put('R', 5.987);
        put('S', 6.327);
        put('T', 9.056);
        put('U', 2.758);
        put('V', 0.978);
        put('W', 2.360);
        put('X', 0.150);
        put('Y', 1.974);
        put('Z', 0.074);
    }};
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
    private String pt;
    private String unknownKey;

    public VigDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.unknownKey = "";
    }

    /**
     * Decrypt with a provided key.
     *
     * @param key The key used to decrypt the ciphertext.
     */
    public String decrypt(String key)
    {
        System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
        decryptPrivate(key);
        return pt;
    }

    /**
     * Decrypt with an unknown key which is an arbitary sequence of letters.
     *
     * @param keyLen Length of the unknown key.
     */
    public String decrypt(int keyLen)
    {
        System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
        findKey(keyLen);
        decryptPrivate(unknownKey);
        return pt;
    }

    /**
     * Decrypt with an unknown key which is an arbitary sequence of letters.
     *
     * @param smallestKeyLen Smallest possible length of the unknown key.
     * @param largestKeyLen  Largest possible length of the unknown key.
     */
    public String decrypt(int smallestKeyLen, int largestKeyLen)
    {
        System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
        ArrayList<String> potentialKeys = new ArrayList<>();
        // Populate potentialKeys, for each keyLen between smallestKeyLen and largestKeyLen (inclusive),
        // find the most likely key for each key length
        for (int i = smallestKeyLen; i <= largestKeyLen; i++) {
            findKey(i);
            potentialKeys.add(unknownKey);
            unknownKey = "";
        }
        System.out.println("Potential Keys: " + potentialKeys);
        // Generate a potential decrypted plaintext for each potential key
        LinkedHashMap<String, String> potentialDecryptedPlaintexts = new LinkedHashMap<>();
        for (String key : potentialKeys) {
            decryptPrivateNoTest(key);
            potentialDecryptedPlaintexts.put(key, pt);
            pt = "";
        }
        // Count the number of times common pairs and repeats in the english language
        // occur in each potential plaintext
        LinkedHashMap<String, Integer> occurrences = new LinkedHashMap<>();
        for (int i = 0; i < potentialDecryptedPlaintexts.size(); i++) {
            int totalOccurrences = 0;
            for (String commonPairOrRepeat : ENGLISH_COMMON_PAIRS_AND_REPEATS) {
                int lastIndex = 0;
                while (lastIndex != -1) {
                    lastIndex = potentialDecryptedPlaintexts.get(potentialKeys.get(i)).indexOf(commonPairOrRepeat, lastIndex);
                    if (lastIndex != -1) {
                        totalOccurrences++;
                        lastIndex += commonPairOrRepeat.length();
                    }
                }
            }
            occurrences.put(potentialKeys.get(i), totalOccurrences);
        }
        // The plaintext with the highest count of occurrences will most likely be english
        String keyMaximumOccurrences = Objects.requireNonNull(occurrences.entrySet().stream().max(Map.Entry.comparingByValue()).orElse(null)).getKey();
        String decryptedPlaintext = potentialDecryptedPlaintexts.get(keyMaximumOccurrences);
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Key: " + keyMaximumOccurrences);
            System.out.println();
            pt = decryptedPlaintext;
        }
        return pt;
    }

    // Decrypt with known key
    private void decryptPrivate(String key)
    {
        String decryptedPlaintext = decryptPrivateHelper(key);
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Key: " + key);
            System.out.println();
            pt = decryptedPlaintext;
        }
    }

    // Decrypt with known key, though do not test to see if plaintext is in tess??.txt
    private void decryptPrivateNoTest(String key)
    {
        pt = decryptPrivateHelper(key);
    }

    private String decryptPrivateHelper(String key)
    {
        StringBuilder decryptedPlaintext = new StringBuilder();
        char[] keyCharacters = key.toCharArray();
        int charAlphaLen = charAlphabet.length;
        int i = 0;
        // For each character in the cipher text.
        for (char character : ciphertext.toCharArray()) {
            // The value of the character in the cipher text.
            int a = findIndex(charAlphabet, character);
            // The value of the character in the provided key.
            int b = findIndex(charAlphabet, keyCharacters[(i % key.length())]);
            decryptedPlaintext.append(charAlphabet[(charAlphaLen + (a - b)) % charAlphaLen]);
            i++;
        }
        return decryptedPlaintext.toString();
    }

    // Find the most likely key of a certain length.
    private void findKey(int keyLen)
    {
        ArrayList<String> charsAtKeyOccurrences = genCharsAtKeyOccurrences(keyLen);
        // Create blank letterOccurrences data array.
        ArrayList<HashMap<Character, Integer>> letterOccurrences = new ArrayList<>();
        for (int i = 0; i < keyLen; i++) {
            HashMap<Character, Integer> blank = new HashMap<>();
            for (char c : charAlphabet) {
                blank.put(c, 0);
            }
            letterOccurrences.add(blank);
        }
        // Populate letterOccurrences
        for (int i = 0; i < charsAtKeyOccurrences.size(); i++) {
            for (char c : charsAtKeyOccurrences.get(i).toCharArray()) {
                HashMap<Character, Integer> singleLetterOccurrences = letterOccurrences.get(i);
                singleLetterOccurrences.put(c, singleLetterOccurrences.get(c) + 1);
            }
        }
        // Create blank letterOccurrenceFreq data array.
        ArrayList<LinkedHashMap<Character, Double>> letterOccurrenceFreq = new ArrayList<>();
        for (int i = 0; i < keyLen; i++) {
            LinkedHashMap<Character, Double> blank = new LinkedHashMap<>();
            for (char c : charAlphabet) {
                blank.put(c, (double) 0);
            }
            letterOccurrenceFreq.add(blank);
        }
        // Populate letterOccurrenceFreq
        for (int i = 0; i < letterOccurrenceFreq.size(); i++) {
            for (char c : charAlphabet) {
                letterOccurrenceFreq.get(i).put(c, (double) letterOccurrences.get(i).get(c) / charsAtKeyOccurrences.get(i).length());
            }
        }
        // Find letter for each index of key
        for (LinkedHashMap<Character, Double> characterDoubleLinkedHashMap : letterOccurrenceFreq) {
            ArrayList<Double> singleLetterOccurrenceFreq = new ArrayList<>(characterDoubleLinkedHashMap.values());
            ArrayList<Double> englishLetterFreq = new ArrayList<>(FREQUENCY_OF_LETTERS_IN_ENGLISH.values());
            ArrayList<Double> ansFreq = new ArrayList<>();
            for (int j = 0; j < singleLetterOccurrenceFreq.size(); j++) {
                double count = 0;
                for (int k = 0; k < englishLetterFreq.size(); k++) {
                    int ind = (k + j) % englishLetterFreq.size();
                    count += (singleLetterOccurrenceFreq.get(ind) * englishLetterFreq.get(k));
                }
                ansFreq.add(count);
            }
            unknownKey += charAlphabet[ansFreq.indexOf(Collections.max(ansFreq))];
        }
    }

    // Generate an ArrayList<String> containing all String of chars
    // which fall on the same letter of the key.
    private ArrayList<String> genCharsAtKeyOccurrences(int keyLen)
    {
        ArrayList<String> tmp = new ArrayList<>();
        for (int i = 0; i < ciphertext.length(); i++) {
            int cIndexOfKey = i % keyLen;
            if (cIndexOfKey < tmp.size()) {
                String newString = tmp.get(cIndexOfKey) + ciphertext.charAt(i);
                tmp.set(cIndexOfKey, newString);
            } else {
                tmp.add(ciphertext.substring(i, i + 1));
            }
        }
        return tmp;
    }
}
