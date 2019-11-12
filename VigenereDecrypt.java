import javafx.util.Pair;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

/**
 * Decryption of ciphertext encoded with a Vigenere Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class VigenereDecrypt extends Decrypt
{
    private String pt;
    private boolean plaintextFound;
    private String unknownKey;

    public VigenereDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.plaintextFound = false;
        this.unknownKey = "";
    }

    /**
     * Decrypt with a provided key.
     *
     * @param key The key used to decrypt the ciphertext.
     */
    public String decrypt(String key)
    {
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
        if (keyLen == 1) {
            for (char c : charAlphabet) {
                decryptPrivate(Character.toString(c));
                if (plaintextFound) {
                    return pt;
                }
            }
        }
        ArrayList<String> charsAtKeyOccurrences = genCharsAtKeyOccurrences(keyLen);
        ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> potentialKeyLetters = new ArrayList<>();
        if (ciphertext.length() >= (keyLen * 2)) {
            System.out.println("Here - ciphertext.length() >= (keyLen * 2");
            potentialKeyLetters = genPotentialKeyLetters(charsAtKeyOccurrences, keyLen);
            System.out.println("potentialKeyLetters: " + potentialKeyLetters);
            findKey(potentialKeyLetters, keyLen);
            System.out.println("unknownKey: " + unknownKey);
            System.out.println();
            if (!unknownKey.equals("")) {
                decryptPrivate(unknownKey);
                return pt;
            } else {
                System.out.println("Could not find the unknownKey");
                return pt;
            }

        } else {
            System.out.println("ciphertext.length() < (keyLen * 2)");
        }
        return pt;
    }

    private void decryptPrivate(String key)
    {
        System.out.println("Here - decryptPrivate");
        String decryptedPlaintext = "";
        char[] keyCharacters = key.toCharArray();
        int charAlphaLen = charAlphabet.length;
        int i = 0;
        // For each character in the cipher text.
        for (char character : ciphertext.toCharArray()) {
            // The value of the character in the cipher text.
            int a = findIndex(charAlphabet, character);
            // The value of the character in the provided key.
            int b = findIndex(charAlphabet, keyCharacters[(i % key.length())]);
            decryptedPlaintext += charAlphabet[(charAlphaLen + (a - b)) % charAlphaLen];
            i++;
        }
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Key: " + key);
            System.out.println();
            pt = decryptedPlaintext;
            plaintextFound = true;
        }
    }

    private ArrayList<String> genCharsAtKeyOccurrences(int keyLen)
    {
        System.out.println("Here - genCharsAtKeyOccurrences");
        ArrayList<String> tmp = new ArrayList<>();
        for (int i = 0; i < ciphertext.length(); i++) {
            int cIndexOfKey = i % keyLen;
            if (cIndexOfKey < tmp.size()) {
                // Concatenate to end of value stored at index
                String newString = tmp.get(cIndexOfKey) + ciphertext.substring(i, i + 1);
                tmp.set(cIndexOfKey, newString);
            } else {
                // Normal add
                tmp.add(ciphertext.substring(i, i + 1));
            }
        }
        return tmp;
    }

    private ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> genPotentialKeyLetters(ArrayList<String> charsAtKeyOccurrences, int keyLen)
    {
        System.out.println("Here - genPotentialKeyLetters");
        ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> tmpPotentialKeyLetters = new ArrayList<>();
        // Each letter in a key, (1 in (keyLen = 6))
        for (String charsAtKeyOccurrence : charsAtKeyOccurrences) {
            ArrayList<Pair<ArrayList<Integer>, Character>> potentialKeysForLetter = new ArrayList<>();
            // FF, index 0 of key
            char[] charArray = charsAtKeyOccurrence.toCharArray();
            // Each char in charArray will decrypt with the same key
            for (char c : charAlphabet) {
                // charArray decrypted with a given c from charAlphabet
                char[] decryptedArray = decryptCharsOfSameKeyOccurrences(charArray, c);
                ArrayList<ArrayList<Integer>> aIFCA = new ArrayList<>();
                boolean nextC = false;
                nextC:
                // Generates aIFCA: allIndexesForCharArray
                for (int j = 0; j < decryptedArray.length; j++) {
                    char decryptedJ = decryptedArray[j];
                    if (tess.contains(Character.toString(decryptedJ))) {
                        for (int i = -1; (i = tess.indexOf(decryptedJ, i + 1)) != -1; i++) {
                            if (j == aIFCA.size()) {
                                ArrayList<Integer> tmp = new ArrayList<>();
                                tmp.add(i);
                                aIFCA.add(tmp);
                            } else {
                                ArrayList<Integer> tmp = new ArrayList<>(aIFCA.get(j));
                                tmp.add(i);
                                aIFCA.set(j, tmp);
                            }
                        }
                    } else {
                        nextC = true;
                        break nextC;
                    }
                }
                if (nextC) {
                    continue;
                }
                ArrayList<Integer> indexes = new ArrayList<>();
//                int index = 0;
                boolean nextK;
                outerloop:
                for (int k = 0; k < aIFCA.get(0).size(); k++) {
                    nextK = false;
                    ArrayList<Integer> tmpIndexes = new ArrayList<>();
                    boolean firstTime = true;
                    int num0 = aIFCA.get(0).get(k);
                    int num1 = num0;
                    for (int l = 1; l < aIFCA.size(); l++) {
                        num1 += keyLen;
                        if (aIFCA.get(l).contains(num1)) {
                            if (firstTime) {
                                tmpIndexes.add(num0);
                                tmpIndexes.add(num1);
                                firstTime = false;
                            } else {
                                tmpIndexes.add(num1);
                            }
                        } else {
                            nextK = true;
                            break;
                        }
                    }
                    if (nextK) {
                        continue;
                    }
                    if (tmpIndexes.size() == aIFCA.size()) {
                        indexes.addAll(tmpIndexes);
                        break outerloop;
                    }
                }
                if (!indexes.isEmpty()) {
                    potentialKeysForLetter.add(new Pair<>(indexes, c));
                    // TODO third draft -
                    //  unknownKey += Character.toString(c); // C [0] // unknownKey == "C"
                    //  try A-Z on the next index, to try build the key,
                    //  if the next A-Z does find the next in the path ([ ?+1, ?+1, ?+1 ]=Q) // Q [1]
                    //   unknownKey += Character.toString(c); // Q [1] // unknownKey == "CQ"
                    //  if the next A-Z doesn't find the next in the path // Q [1]
                    //   go to // D [0]
                    //  continue until // unknownKey == "TESSOF" [0-5] has been found
                }

            }
            tmpPotentialKeyLetters.add(potentialKeysForLetter);
        }
        return tmpPotentialKeyLetters;
    }

    // Decrypts each char, in an array of chars, with a a single character key
    // ciphertext = FF, key = T, plaintext = MM
    private char[] decryptCharsOfSameKeyOccurrences(char[] charsOfSameKeyOccurrences, char key)
    {
        System.out.println("Here - decryptCharsOfSameKeyOccurrences");
        String decryptedPlaintext = "";
        int charAlphaLen = charAlphabet.length;
        for (char c : charsOfSameKeyOccurrences) {
            // The index of the character in the cipher text, in the charAlphabet.
            int a = findIndex(charAlphabet, c);
            // The index of the key, in the charAlphabet.
            int b = findIndex(charAlphabet, key);
            int index = (charAlphaLen + (a - b)) % charAlphaLen;
            decryptedPlaintext += charAlphabet[index];
        }
        return decryptedPlaintext.toCharArray();
    }

    // Checks all possibleKeyLetters, generates a set of possibleLetters,
    // the set with the same size as the keyLen will be the required decryption key.
    private void findKey(ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> potentialKeyLetters, int keyLen)
    {
        System.out.println("Here - findKey");
        // Find keys which increment between each successive index.
        ArrayList<ArrayList<Character>> possibleLetters = new ArrayList<>();
        int overallIndex = 0;
        int index = 0;
        // For all in the first letter slot, of a key
        for (int k = 0; k < potentialKeyLetters.get(index).size(); k++) {
            // Add first letter to possible letters
            ArrayList<Character> initialChar = new ArrayList<>();
            initialChar.add(potentialKeyLetters.get(index).get(k).getValue());
            possibleLetters.add(initialChar);
            Pair<ArrayList<Integer>, Character> occurrences = potentialKeyLetters.get(index).get(k);
            outerloop:
            // For sets of potential key letters, coincidentally the same size a keyLen
            for (int l = 1; l < potentialKeyLetters.size(); l++) {
                ArrayList<Integer> addedToList = incrementEachElementInList(occurrences.getKey());
                char lookedUp = lookupChar(l, addedToList, potentialKeyLetters);
                if (lookedUp == '?') {
                    break outerloop;
                }
                Pair<ArrayList<Integer>, Character> occurrences1 = new Pair<>(addedToList, lookedUp);
                innerloop:
                // For the all in a given letter slot, of a key
                for (int i = 0; i < potentialKeyLetters.get(l).size(); i++) {
                    ArrayList<Integer> x = potentialKeyLetters.get(l).get(i).getKey();
                    ArrayList<Integer> occurrences1Key = occurrences1.getKey();
                    if (x.size() == occurrences1Key.size()) {
                        // [?, ?, ?] == [?, ?, ?]
                        if (x.equals(occurrences1Key)) {
                            ArrayList<Character> tmp = new ArrayList<>(possibleLetters.get(overallIndex));
                            tmp.add(occurrences1.getValue());
                            possibleLetters.set(overallIndex, tmp);
                            occurrences = occurrences1;
                            break innerloop;
                        }
                    } else {
                        // [?, ?] == [?, ?, ?]
                        boolean checked = true;
                        for (int j = 0; j < x.size(); j++) {
                            if (x.get(j) != occurrences1Key.get(j)) {
                                checked = false;
                                break;
                            }
                        }
                        if (checked) {
                            ArrayList<Character> tmp = new ArrayList<>(possibleLetters.get(overallIndex));
                            tmp.add(occurrences1.getValue());
                            possibleLetters.set(overallIndex, tmp);
                            occurrences = occurrences1;
                            break innerloop;
                        }
                    }
                }
            }
            overallIndex++;
        }
        setUnknownKey(possibleLetters, keyLen);
    }

    private ArrayList<Integer> incrementEachElementInList(ArrayList<Integer> list)
    {
        System.out.println("Here - incrementEachElementInList");
        ArrayList<Integer> tmp = new ArrayList<>(list);
        if (!tmp.isEmpty()) {
            for (int i = 0; i < tmp.size(); i++) {
                tmp.set(i, (tmp.get(i) + 1));
            }
        }
        return tmp;
    }

    // Look the next char for the given potentialKeysForLetter of the next letter
    private char lookupChar(int index, ArrayList<Integer> addedToList, ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> potentialKeyLetters)
    {
        System.out.println("Here - lookupChar");
        for (Pair<ArrayList<Integer>, Character> p : potentialKeyLetters.get(index)) {
            ArrayList<Integer> xList = p.getKey();
            int x = xList.size();
            int y = addedToList.size();
            if (x == y) {
                // [?, ?, ?] == [?, ?, ?]
                if (xList.equals(addedToList)) {
                    return p.getValue();
                }
            } else {
                // [?, ?] == [?, ?, ?]
                boolean checked = true;
                for (int i = 0; i < x; i++) {
                    if (xList.get(i) != addedToList.get(i)) {
                        checked = false;
                    }
                }
                if (checked) {
                    return p.getValue();
                }
            }
        }
        // Can't find addedToList in the potentialKeysForLetter of the next letter
        return '?';
    }

    // From the list of possibleLetters, only the one the same size
    // as the key will be the required decryption key.
    private void setUnknownKey(ArrayList<ArrayList<Character>> possibleLetters, int keyLen)
    {
        System.out.println("Here - setUnknownKey");
        for (ArrayList<Character> arrayP : possibleLetters) {
            if (arrayP.size() == keyLen) {
                for (char c : arrayP) {
                    unknownKey += Character.toString(c);
                }
            }
        }
    }
}
