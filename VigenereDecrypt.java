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

        // keyLen > 1

        int ctLen = ciphertext.length();
        int ct_mod = ctLen % keyLen;
        int div_into = (ctLen - ct_mod) / keyLen;
        ArrayList<String> charsAtKeyOccurrences = genCharsAtKeyOccurrences(keyLen);

        ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> potentialKeyLetters = new ArrayList<>();

        if (ciphertext.length() >= (keyLen * 2)) {
            // Each letter in a key
            // (1 in (keyLen = 6))
            for (int i = 0; i < charsAtKeyOccurrences.size(); i++) {
                ArrayList<Pair<ArrayList<Integer>, Character>> potentialKeysForLetter = new ArrayList<>();
                // FF
                // index 0 of key
                char[] charArray = charsAtKeyOccurrences.get(i).toCharArray();
                // Each char in charArray will decrypt with the same key
                for (char c : charAlphabet) {
                    // FF decrypted with a given c from charAlphabet
                    String decrypted = decryptCharsOfSameKeyOccurrences(charArray, c);
                    char[] decryptedArray = decrypted.toCharArray();
                    // Check to see if tess contains all chars in decrypted
                    boolean containsAll = true;
                    for (char decryptC : decryptedArray) {
                        if (!tess.contains(Character.toString(decryptC))) {
                            containsAll = false;
                        }
                    }
                    // If tess contains all chars in decrypted
                    if (containsAll) {
                        // {
                        // {all indexes for charArray[0]},
                        // {all indexes for charArray[1]},
                        // {all indexes for charArray[2]},
                        // ...
                        // }
                        ArrayList<ArrayList<Integer>> ind = new ArrayList<>();
                        char[] tessArray = tess.toCharArray();
                        for (int k = 0; k < decryptedArray.length; k++) {
                            for (int l = 0; l < tessArray.length; l++) {
                                char tessC = tessArray[l];
                                if (tessC == decryptedArray[k]) {
                                    ArrayList<Integer> tmp;
                                    if (k <= (ind.size() - 1)) {
                                        tmp = new ArrayList<>(ind.get(k));
                                    } else {
                                        tmp = new ArrayList<>();
                                    }
                                    tmp.add(l);
                                    if (k <= (ind.size() - 1)) {
                                        ind.set(k, tmp);
                                    } else {
                                        ind.add(tmp);
                                    }
                                }
                            }
                        }
                        // [
                        // [9, 15, 21, 47, 48, 49],
                        // [9, 15, 21, 47, 48, 49],
                        // [9, 15, 21, 47, 48, 49],
                        // ]
                        ArrayList<Integer> indexes = new ArrayList<>();
                        int index = 0;
                        outerloop:
                        for (int k = 0; k < ind.get(index).size(); k++) {
                            ArrayList<Integer> tmpIndexes = new ArrayList<>();
                            boolean firstTime = true;
                            int num = ind.get(index).get(k);
                            for (int l = 1; l < ind.size(); l++) {
                                int num1 = num + keyLen;
                                if (ind.get(l).contains(num1)) {
                                    if (firstTime) {
                                        tmpIndexes.add(num);
                                        tmpIndexes.add(num1);
                                        firstTime = false;
                                        num = num1;
                                    } else {
                                        tmpIndexes.add(num1);
                                        num = num1;
                                    }
                                }
                            }
                            if (tmpIndexes.size() == ind.size()) {
                                indexes.addAll(tmpIndexes);
                                break outerloop;
                            }
                        }
                        // [9, 15, 21]
                        if (!indexes.isEmpty()) {
                            potentialKeysForLetter.add(new Pair<>(indexes, c));
                        }
                    } // end if statement
                } // end for loop
                potentialKeyLetters.add(potentialKeysForLetter);
            } //end for loop
            System.out.println();  // Debug/Check potentialKeyLetters data array entry point

            // Find keys which increment between each successive index.
            ArrayList<ArrayList<Character>> possibleLetters = new ArrayList<>();
            int overallIndex = 0;
            int index = 0;
            for (int k = 0; k < potentialKeyLetters.get(index).size(); k++) {
                // Add first letter to possible letters
                ArrayList<Character> initialChar = new ArrayList<>();
                initialChar.add(potentialKeyLetters.get(index).get(k).getValue());
                possibleLetters.add(initialChar);
                Pair<ArrayList<Integer>, Character> occurrences = potentialKeyLetters.get(index).get(k);
                outerloop:
                for (int l = 1; l < potentialKeyLetters.size(); l++) {
                    ArrayList<Integer> addedToList = addToEachElementInList(occurrences.getKey());
                    char lookedUp = lookupChar(l, addedToList, potentialKeyLetters);
                    if (lookedUp == '?') {
                        break outerloop;
                    }
                    Pair<ArrayList<Integer>, Character> occurrences1 = new Pair<>(addedToList, lookedUp);
                    innerloop:
                    for (int i = 0; i < potentialKeyLetters.get(l).size(); i++) {
                        ArrayList<Integer> x = potentialKeyLetters.get(l).get(i).getKey();
                        ArrayList<Integer> occurrences1Key = occurrences1.getKey();
                        if (x.size() == occurrences1Key.size()) {
                            if (x.equals(occurrences1Key)) {
                                ArrayList<Character> tmp = new ArrayList<>(possibleLetters.get(overallIndex));
                                tmp.add(occurrences1.getValue());
                                possibleLetters.set(overallIndex, tmp);
                                occurrences = occurrences1;
                                break innerloop;
                            }
                        } else {
                            boolean checked = true;
                            for (int j = 0; j < x.size(); j++) {
                                if (x.get(i) != occurrences1Key.get(i)) {
                                    checked = false;
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

            // From the list of possibleLetters, only the one the same size
            // as the key will be the required decryption key.

            for (ArrayList<Character> arrayP : possibleLetters) {
                if (arrayP.size() == keyLen) {
                    for (char c : arrayP) {
                        unknownKey += Character.toString(c);
                    }
                }
            }

            System.out.println("Key is: " + unknownKey);
        } else {
            System.out.println("ciphertext.length() < (keyLen * 2)");
        }

        return "";
    }

    private char lookupChar(int index, ArrayList<Integer> addedToList,
            ArrayList<ArrayList<Pair<ArrayList<Integer>, Character>>> potentialKeyLetters)
    {
        for (Pair<ArrayList<Integer>, Character> p : potentialKeyLetters.get(index)) {
            ArrayList<Integer> xList = p.getKey();
            int x = xList.size();
            int y = addedToList.size();
            if (x == y) {
                if (xList.equals(addedToList)) {
                    return p.getValue();
                }
            } else {
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
        return '?';
    }

    private ArrayList<Integer> addToEachElementInList(ArrayList<Integer> list)
    {
        ArrayList<Integer> tmp = new ArrayList<>(list);
        if (!tmp.isEmpty()) {
            for (int i = 0; i < tmp.size(); i++) {
                tmp.set(i, (tmp.get(i) + 1));
            }
        }
        return tmp;
    }

    // ciphertext = FF
    // key = T
    // plaintext = MM
    public String decryptCharsOfSameKeyOccurrences(char[] charsOfSameKeyOccurrences, char key)
    {
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
        return decryptedPlaintext;
    }

    private ArrayList<String> genCharsAtKeyOccurrences(int keyLen)
    {
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

    private void decryptPrivate(String key)
    {
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
        // If the tess??.txt file contains the decrypted plaintext,
        // it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Key: " + key);
            System.out.println();
            pt = decryptedPlaintext;
            plaintextFound = true;
        }
    }

//    private ArrayList<Integer> genKeyIndexOccurrences(int keyLen, int ct_mod, int div_into)
//    {
//        ArrayList<Integer> tmp = new ArrayList<>();
//        for (int i = 1; i <= keyLen; i++) {
//            if (i <= ct_mod) {
//                tmp.add((div_into + 1));
//            } else {
//                tmp.add(div_into);
//            }
//        }
//        return tmp;
//    }

//    // The method that tries all decryption keys of a given length k.
//    // It is mainly a wrapper over recursive function checkAllKeysRec()
//    private void checkAllKeys(char[] set, int k)
//    {
//        int setLen = set.length;
//        helper(set, setLen, "", k, k, 0, setLen - 1);
//    }
//
//    private void helper(char[] set, int setLen, String prefix, int originalK, int k, int startIndex, int endIndex)
//    {
//        int diffIndex = (endIndex - startIndex) + 1;
//        if (diffIndex <= 3) {
//            for (int i = 0; i < diffIndex; i++) {
//                String tmp = "";
//                for (int j = 0; j < (originalK - k); j++) {
//                    tmp += set[startIndex + i];
//                }
//                prefix = tmp;
////                System.out.println(prefix);
//                checkAllKeysRec(set, setLen, prefix, k);
//            }
//        } else {
//            int a1 = startIndex;
//            int a2 = startIndex + (diffIndex >> 1) - 1;
//            int b1 = startIndex + (diffIndex >> 1);
//            int b2 = endIndex - 1;
//            int c = endIndex;
//            if ((diffIndex & 1) != 0) {
//                // k is odd
////                System.out.println(a1 + " " + a2);
////                System.out.println(b1 + " " + b2);
////                System.out.println(c + " " + c);
//                helper(set, setLen, prefix + set[a1], originalK,k - 1, a1, a2);
//                helper(set, setLen, prefix + set[b1], originalK, k - 1, b1, b2);
//                helper(set, setLen, prefix + set[c], originalK, k - 1, c, c);
//            } else {
//                // k is even
////                System.out.println(a1 + " " + a2);
////                System.out.println(b1 + " " + c);
//                helper(set, setLen, prefix + set[a1], originalK, k - 1, a1, a2);
//                helper(set, setLen, prefix + set[b1], originalK, k - 1, b1, c);
//            }
//        }
//    }
//
//    // The main recursive method to try decryption with all possible strings of length k.
//    private void checkAllKeysRec(char[] set, int setLen, String prefix, int k)
//    {
//        // Base case: k is 0, print prefix
//        if (k != 0) {
//            // One by one add all characters from set and recursively call for k equals to k-1
//            for (int i = 0; i < setLen; ++i) {
//                // Next character of input added
//                String newPrefix = prefix + set[i];
//                // k is decreased, because we have added a new character
//                checkAllKeysRec(set, setLen, newPrefix, k - 1);
//            }
//        } else {
//            System.out.println(prefix);
//            decryptPrivate(prefix);
//            if (tess.contains(pt)) {
//                // We've found our plaintext.
//                return;
//            }
//        }
//    }
}
