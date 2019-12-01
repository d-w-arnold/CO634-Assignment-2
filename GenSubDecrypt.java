import javafx.util.Pair;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Decryption of ciphertext encoded with a General Substitution Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class GenSubDecrypt extends Decrypt
{
    final private ArrayList<Character> ENGLISH_FREQUENCY_ORDER = new ArrayList<Character>()
    {{
        add('|');
        add('E');
        add('T');
        add('A');
        add('O');
        add('I');
        add('N');
        add('S');
        add('H');
        add('R');
        add('D');
        add('L');
        add('C');
        add('U');
        add('M');
        add('W');
        add('F');
        add('G');
        add('Y');
        add('P');
        add('B');
        add('V');
        add('K');
        add('J');
        add('X');
        add('Q');
        add('Z');
    }};
    final private ArrayList<String> ENGLISH_ONE_LETTER_WORDS = new ArrayList<String>()
    {{
        add("A");
        add("I");
    }};
    final private ArrayList<String> ENGLISH_TWO_LETTER_WORDS = new ArrayList<String>()
    {{
        add("OF");
        add("TO");
        add("IN");
        add("IT");
        add("IS");
        add("BE");
        add("AS");
        add("AT");
        add("SO");
        add("WE");
        add("HE");
        add("BY");
        add("OR");
        add("ON");
        add("DO");
        add("IF");
        add("ME");
        add("MY");
        add("UP");
        add("AN");
        add("GO");
        add("NO");
        add("US");
        add("AM");
    }};
    final private ArrayList<String> ENGLISH_THREE_LETTER_WORDS = new ArrayList<String>()
    {{
        add("THE");
        add("AND");
        add("FOR");
        add("ARE");
        add("BUT");
        add("NOT");
        add("YOU");
        add("ALL");
        add("ANY");
        add("CAN");
        add("HAD");
        add("HER");
        add("WAS");
        add("ONE");
        add("OUR");
        add("OUT");
        add("DAY");
        add("GET");
        add("HAS");
        add("HIM");
        add("HIS");
        add("HOW");
        add("MAN");
        add("NEW");
        add("NOW");
        add("OLD");
        add("SEE");
        add("TWO");
        add("WAY");
        add("WHO");
        add("BOY");
        add("DID");
        add("ITS");
        add("LET");
        add("PUT");
        add("SAY");
        add("SHE");
        add("TOO");
        add("USE");
    }};
    final private ArrayList<String> ENGLISH_FOUR_LETTER_WORDS = new ArrayList<String>()
    {{
        add("THAT");
        add("WITH");
        add("HAVE");
        add("THIS");
        add("WILL");
        add("YOUR");
        add("FROM");
        add("THEY");
        add("KNOW");
        add("WANT");
        add("BEEN");
        add("GOOD");
        add("MUCH");
        add("SOME");
        add("TIME");
    }};
    final private ArrayList<String> ENGLISH_DIGRAPHS = new ArrayList<String>()
    {{
        add("TH");
        add("ER");
        add("ON");
        add("AN");
        add("RE");
        add("HE");
        add("IN");
        add("ED");
        add("ND");
        add("HA");
        add("AT");
        add("EN");
        add("ES");
        add("OF");
        add("OR");
        add("NT");
        add("EA");
        add("TI");
        add("TO");
        add("IT");
        add("ST");
        add("IO");
        add("LE");
        add("IS");
        add("OU");
        add("AR");
        add("AS");
        add("DE");
        add("RT");
        add("VE");
    }};
    final private ArrayList<String> ENGLISH_TRIGRAPHS = new ArrayList<String>()
    {{
        add("THE");
        add("AND");
        add("THA");
        add("ENT");
        add("ION");
        add("TIO");
        add("FOR");
        add("NDE");
        add("HAS");
        add("NCE");
        add("EDT");
        add("TIS");
        add("OFT");
        add("STH");
        add("MEN");
    }};
    private String pt;
    // Key: letter in ciphertext, Value: most likely mapped letter based on frequency of occurrence
    private ArrayList<Pair<Character, Character>> mappedLetters;
    // Key: letter in part decrypted ciphertext from just letter frequency analysis, Value: most likely mapped letter based on word frequency analysis
    private LinkedHashMap<Character, Character> mappedLetters2;
    // Key: letter in part decrypted ciphertext from just letter frequency analysis, Value: a letter mapping to itself based of word frequency analysis
    private LinkedHashMap<Character, Character> mappedLetters2DuplicateKeyValue;
    // For each word in the part decrypted ciphertext, records the most common english words of the same length
    private ArrayList<Pair<String, ArrayList<String>>> mostSimilaritiesForEachWord;
    // For each word in the mostSimilaritiesForEachWord, records the necessary letter mappings to acquire to each word
    private ArrayList<Pair<String, ArrayList<ArrayList<Pair<Character, Character>>>>> mostSimilaritiesForEachWordMappings;
    // Key: a one letter potentialWord, Value: the number of occurrences for the one letter word
    private HashMap<String, Integer> oneLetterPotentialWordsOccurrences;

    public GenSubDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.mappedLetters = new ArrayList<>();
        this.mostSimilaritiesForEachWord = new ArrayList<>();
        this.mostSimilaritiesForEachWordMappings = new ArrayList<>();
        this.mappedLetters2 = new LinkedHashMap<>();
        this.mappedLetters2DuplicateKeyValue = new LinkedHashMap<Character, Character>()
        {{
            put('|', '|');
        }};
        this.oneLetterPotentialWordsOccurrences = new HashMap<>();
    }

    /**
     * Decrypt a General Substitution Cipher.
     */
    public String decrypt()
    {
        System.out.println(getExercise(cipherFile) + ": General Substitution Cipher");
        // Generate characterCounts containing count of each letter from charAlphabet in the ciphertext
        ArrayList<Pair<Character, Integer>> characterCounts = new ArrayList<>();
        genCharacterCounts(ciphertext, characterCounts);
        // Sort characterCounts into descending order for count
        characterCounts.sort((o1, o2) -> {
            if (o1.getValue() > o2.getValue()) {
                return -1;
            } else if (o1.getValue().equals(o2.getValue())) {
                return 0;
            } else {
                return 1;
            }
        });
        // Generate String representation of initial character mappings
        for (int i = 0; i < characterCounts.size(); i++) {
            mappedLetters.add(new Pair<>(characterCounts.get(i).getKey(), ENGLISH_FREQUENCY_ORDER.get(i)));
        }
        // Generate mappedString - the current letter mappings after letter frequency analysis
        String mappedString = "";
        for (Pair<Character, Integer> characterCount : characterCounts) {
            mappedString += characterCount.getKey();
        }
        // Generate initial decrypted plaintext from mappedLetters
        String decryptedPlaintext = "";
        for (char ctChar : ciphertext.toCharArray()) {
            for (Pair<Character, Character> mappedLetter : mappedLetters) {
                if (mappedLetter.getKey() == ctChar) {
                    decryptedPlaintext += mappedLetter.getValue();
                }
            }
        }
        pt = decryptedPlaintext;
        // Separate decrypted plaintext into potentialWords separated by '|',
        // as '|' can represent a space, this will be the most frequently
        // occurring character in the part decrypted plaintext
        String[] separated = pt.split("\\|");
        ArrayList<String> potentialWords = new ArrayList<>(Arrays.asList(separated));
        // Record any one letter occurrences and how many of each
        popOneLetterPotentialWordsOccurrences(potentialWords);
        // Populate mostSimilaritiesForEachWord, any English words found will be removed
        // and their letter mappings added to mappedLetters2DuplicateKeyValue
        popMostSimilaritiesForEachWord(containsEnglishWords(potentialWords));
        // Remove duplicates from mostSimilaritiesForEachWord
        mostSimilaritiesForEachWord = removeDuplicates(mostSimilaritiesForEachWord);
        // Populate mostSimilaritiesForEachWordMappings
        popMostSimilaritiesForEachWordMappings();
        // Generate mappedLetter2 and mappedLetter2DuplicateKeyValue using most common 1, 2, 3 and 4 letter words - word frequency analysis
        for (int i = 0; i < mostSimilaritiesForEachWordMappings.size(); ) {
            // Clauses for discarding words in mostSimilaritiesForEachWord and mostSimilaritiesForEachWordMappings
            if (mostSimilaritiesForEachWordMappings.get(i).getValue().isEmpty()) {
                mostSimilaritiesForEachWord.remove(i);
                mostSimilaritiesForEachWordMappings.remove(i);
                continue;
            }
            ArrayList<Pair<Character, Character>> newLetterMappings = mostSimilaritiesForEachWordMappings.get(i).getValue().get(0);
            if (newLetterMappings.isEmpty() && (mostSimilaritiesForEachWord.get(i).getValue().get(0)).equals(mostSimilaritiesForEachWord.get(i).getKey().toUpperCase())) {
                char[] keyCA = mostSimilaritiesForEachWordMappings.get(i).getKey().toCharArray();
                for (char c : keyCA) {
                    if (Character.isUpperCase(c)) {
                        mappedLetters2.put(c, c);
                    }
                }
                mostSimilaritiesForEachWord.remove(i);
                mostSimilaritiesForEachWordMappings.remove(i);
                continue;
            }
            // Added some found letter mappings to mappedLetters2
            boolean forceContinue = false;
            for (Pair<Character, Character> pair : newLetterMappings) {
                if (!mappedLetters2.containsKey(pair.getKey()) && !mappedLetters2.containsValue(pair.getValue())) {
                    mappedLetters2.put(pair.getKey(), pair.getValue());
                } else {
                    mostSimilaritiesForEachWord.remove(i);
                    mostSimilaritiesForEachWordMappings.remove(i);
                    forceContinue = true;
                }
            }
            if (forceContinue) {
                continue;
            }
            // Using the new letter mappings, generate new potentialWords,
            // and populate mostSimilaritiesForEachWord
            popMostSimilaritiesForEachWord(genNewPotentialWords());
            // Populate mostSimilaritiesForEachWordMappings again as well
            popMostSimilaritiesForEachWordMappings();
            // Move from mappedLetters2 to mappedLetters2DuplicateKeyValue any entries where
            // the key and value are equal
            for (char charAlpha : charAlphabet) {
                if (mappedLetters2.containsKey(charAlpha) && mappedLetters2.get(charAlpha).equals(charAlpha)) {
                    mappedLetters2.remove(charAlpha);
                    mappedLetters2DuplicateKeyValue.put(charAlpha, charAlpha);
                }
            }
            i = 0;
        }
        // Remove from mappedLetters2 where the value of an entry features as a key
        // in mappedLetters2DuplicateKeyValue
        for (char charAlpha : charAlphabet) {
            if (mappedLetters2.containsKey(charAlpha) && mappedLetters2DuplicateKeyValue.containsKey(mappedLetters2.get(charAlpha))) {
                mappedLetters2.remove(charAlpha);
            }
        }
        // Combine mappedLetters2 and mappedLetters2DuplicateKeyValues
        mappedLetters2.putAll(mappedLetters2DuplicateKeyValue);
        // Generate mappedString2 - the current letter mappings after letter and word frequency analysis
        String mappedString2 = "";
        char[] mappedStringCA = mappedString.toCharArray();
        for (char letter : mappedStringCA) {
            mappedString2 += mappedLetters2.getOrDefault(letter, letter);
        }
        // Generate new decrypted plaintext from mappedLetters2
        String decryptedPlaintext2 = "";
        for (char ptChar : pt.toCharArray()) {
            if (mappedLetters2.containsKey(ptChar)) {
                decryptedPlaintext2 += Character.toLowerCase(mappedLetters2.get(ptChar));
            } else {
                decryptedPlaintext2 += ptChar;
            }
        }
        pt = decryptedPlaintext2;

        // For any letters not yet featuring as keys in mappedLetters2, their letter mappings are still unknown
        // Generate potential letter mappings for all those letters
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCounts = new ArrayList<>();
        genCharacterCounts(mappedString2, mappedString2CharacterCounts);
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsWithoutMappedLetters2Keys = new ArrayList<>();
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsAsZero = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCounts) {
            if (!mappedLetters2.containsKey(pair.getKey())) {
                mappedString2CharacterCountsWithoutMappedLetters2Keys.add(pair);
            }
            if (pair.getValue() == 0) {
                mappedString2CharacterCountsAsZero.add(pair);
            }
        }
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsAsOne = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCountsWithoutMappedLetters2Keys) {
            if (pair.getValue() == 1) {
                mappedString2CharacterCountsAsOne.add(pair);
            }
        }
        ArrayList<Character> zeroLetters = new ArrayList<>();
        ArrayList<Character> oneLetters = new ArrayList<>();
        ArrayList<ArrayList<Character>> permuZeros = new ArrayList<>();
        ArrayList<ArrayList<Character>> permuOnes = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCountsWithoutMappedLetters2Keys) {
            if (pair.getValue() == 2) {
                zeroLetters.add(pair.getKey());
                ArrayList<Character> tmp = new ArrayList<>();
                for (Pair<Character, Integer> zeroPair : mappedString2CharacterCountsAsZero) {
                    tmp.add(zeroPair.getKey());
                }
                permuZeros = listPermutations(tmp);
            } else if (pair.getValue() == 1) {
                oneLetters.add(pair.getKey());
                ArrayList<Character> tmp = new ArrayList<>();
                for (Pair<Character, Integer> onePair : mappedString2CharacterCountsAsOne) {
                    tmp.add(onePair.getKey());
                }
                permuOnes = listPermutations(tmp);
            }
        }
        // Generate zeroLetterMappings, if a letter appears twice in mappedString2,
        // it will map to (for mappedLetters2) one of the letters not present in the mappedString2
        ArrayList<HashMap<Character, Character>> zeroLetterMappings = new ArrayList<>();
        for (ArrayList<Character> permuZero : permuZeros) {
            HashMap<Character, Character> tmpHM = new HashMap<>();
            for (int j = 0; j < permuZero.size(); j++) {
                tmpHM.put(zeroLetters.get(j), permuZero.get(j));
            }
            zeroLetterMappings.add(tmpHM);
        }
        // Generate oneLetterMappings, if a letter appears once in mappedString2 and does not
        // feature as a key in mappedLetters2, it will map to one of the other letters appearing once
        // in mappedString2 which also does not feature in mappedLetters2 - including itself
        ArrayList<HashMap<Character, Character>> oneLetterMappings = new ArrayList<>();
        for (ArrayList<Character> permuOne : permuOnes) {
            HashMap<Character, Character> tmpHM = new HashMap<>();
            for (int j = 0; j < permuOne.size(); j++) {
                tmpHM.put(oneLetters.get(j), permuOne.get(j));
            }
            oneLetterMappings.add(tmpHM);
        }
        // Try each combination of zeroLetterMappings and oneLetterMappings, and record
        // how many digraph and trigraph occurrences each combination of letter mappings yields
        HashMap<HashMap<Character, Character>, Integer> digraphTrigraphOccurrences = new HashMap<>();
        for (HashMap<Character, Character> zeroHM : zeroLetterMappings) {
            for (HashMap<Character, Character> oneHM : oneLetterMappings) {
                HashMap<Character, Character> tmpHM = new HashMap<Character, Character>()
                {{
                    putAll(zeroHM);
                    putAll(oneHM);
                }};
                String tmpPT = pt;
                String newTmpPT = "";
                for (char tmpPTChar : tmpPT.toCharArray()) {
                    if (Character.isUpperCase(tmpPTChar) && tmpHM.containsKey(tmpPTChar)) {
                        newTmpPT += tmpHM.get(tmpPTChar);
                    } else {
                        newTmpPT += tmpPTChar;
                    }
                }
                newTmpPT = newTmpPT.toUpperCase();
                int totalOccurrences = 0;
                for (String digraph : ENGLISH_DIGRAPHS) {
                    int lastIndex = 0;
                    while (lastIndex != -1) {
                        lastIndex = newTmpPT.indexOf(digraph, lastIndex);
                        if (lastIndex != -1) {
                            totalOccurrences++;
                            lastIndex += digraph.length();
                        }
                    }
                }
                for (String trigraph : ENGLISH_TRIGRAPHS) {
                    int lastIndex = 0;
                    while (lastIndex != -1) {
                        lastIndex = newTmpPT.indexOf(trigraph, lastIndex);
                        if (lastIndex != -1) {
                            totalOccurrences++;
                            lastIndex += trigraph.length();
                        }
                    }
                }
                digraphTrigraphOccurrences.put(tmpHM, totalOccurrences);
            }
        }
        // The value of the maximum number of occurrences of digraphs and trigraphs,
        // for any combination(s) of zeroLetterMappings and oneLetterMappings
        int maximum = digraphTrigraphOccurrences.entrySet().stream().max(Comparator.comparing(Map.Entry::getValue)).get().getValue();
        // If a combination of zeroLetterMappings and oneLetterMappings yields
        // the maximum number of diagraph and trigraph occurrences,
        // it a possibility for these remaining letter mappings to yield a correct english
        // decrypted plaintext - try each one.
        for (HashMap<Character, Character> zeroHM : zeroLetterMappings) {
            for (HashMap<Character, Character> oneHM : oneLetterMappings) {
                HashMap<Character, Character> tmpHM = new HashMap<Character, Character>()
                {{
                    putAll(zeroHM);
                    putAll(oneHM);
                }};
                if (digraphTrigraphOccurrences.get(tmpHM) == maximum) {
                    String tmpPT = pt;
                    String newTmpPT = "";
                    for (char tmpPTChar : tmpPT.toCharArray()) {
                        if (Character.isUpperCase(tmpPTChar) && tmpHM.containsKey(tmpPTChar)) {
                            newTmpPT += tmpHM.get(tmpPTChar);
                        } else {
                            newTmpPT += tmpPTChar;
                        }
                    }
                    if (tess.contains(newTmpPT.toUpperCase())) {
                        pt = newTmpPT.toUpperCase();
                        System.out.println("Decrypted: " + pt);
                        String charAlphabetString = "";
                        for (char charAlpha : charAlphabet) {
                            charAlphabetString += charAlpha;
                        }
                        System.out.println("Ciphertext Character Alphabet: " + charAlphabetString);
                        HashMap<Character, Character> fullMappedLetters = new HashMap<Character, Character>()
                        {{
                            putAll(mappedLetters2);
                            putAll(tmpHM);
                        }};
                        String finalMappedString = "";
                        for (char charAlpha : charAlphabet) {
                            for (Pair<Character, Character> pair : mappedLetters) {
                                if (pair.getKey() == charAlpha) {
                                    finalMappedString += fullMappedLetters.get(pair.getValue());
                                }
                            }
                        }
                        System.out.println("------------------------------ " + "↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓");
                        System.out.println("Plaintext Character Mappings:  " + finalMappedString);
                        System.out.println();
                        return pt;
                    }
                }
            }
        }
        return "";
    }

    // Generates all permutations of an ArrayList containing chars
    private ArrayList<ArrayList<Character>> listPermutations(ArrayList<Character> list)
    {
        if (list.size() == 0) {
            ArrayList<ArrayList<Character>> result = new ArrayList<>();
            result.add(new ArrayList<>());
            return result;
        }
        ArrayList<ArrayList<Character>> returnMe = new ArrayList<>();
        char firstElement = list.remove(0);
        ArrayList<ArrayList<Character>> recursiveReturn = listPermutations(list);
        for (List<Character> li : recursiveReturn) {
            for (int index = 0; index <= li.size(); index++) {
                ArrayList<Character> temp = new ArrayList<>(li);
                temp.add(index, firstElement);
                returnMe.add(temp);
            }

        }
        return returnMe;
    }

    // For all letters on charAlphabet, count their occurrences and store in a provided list
    private void genCharacterCounts(String st, ArrayList<Pair<Character, Integer>> list)
    {
        for (char charAlpha : charAlphabet) {
            int totalOccurrences = 0;
            for (char stChar : st.toCharArray()) {
                if (charAlpha == stChar) {
                    totalOccurrences++;
                }
            }
            list.add(new Pair<>(charAlpha, totalOccurrences));
        }
    }

    // Generate new potentialWords, using all letter mappings stored in mappedLetters2
    private ArrayList<String> genNewPotentialWords()
    {
        // Alter all keys in mostSimilaritiesForEachWord
        ArrayList<String> newPotentialWords = new ArrayList<>();
        for (Pair<String, ArrayList<String>> stringArrayListPair : mostSimilaritiesForEachWord) {
            char[] aWordCA = stringArrayListPair.getKey().toCharArray();
            String newWord = "";
            for (char c : aWordCA) {
                if (mappedLetters2.containsKey(c)) {
                    newWord += Character.toLowerCase(mappedLetters2.get(c));
                } else {
                    newWord += c;
                }
            }
            if (!allLowerCase(newWord)) {
                newPotentialWords.add(newWord);
            }
        }
        return newPotentialWords;
    }

    // Returns new potential words and adds to mappedLetters2 any letter used in an english word
    private ArrayList<String> containsEnglishWords(ArrayList<String> potentialWords)
    {
        ArrayList<String> nonEnglishPotentialWords = new ArrayList<>();
        for (String aWord : potentialWords) {
            if (aWord.length() == 1) {
                if (ENGLISH_ONE_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    mappedLetters2DuplicateKeyValue.put(Character.toUpperCase(aWord.charAt(0)), Character.toUpperCase(aWord.charAt(0)));
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 2) {
                if (ENGLISH_TWO_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (char c : aWordCA) {
                        if (Character.isUpperCase(c)) {
                            mappedLetters2DuplicateKeyValue.put(c, c);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 3) {
                if (ENGLISH_THREE_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (char c : aWordCA) {
                        if (Character.isUpperCase(c)) {
                            mappedLetters2DuplicateKeyValue.put(c, c);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 4) {
                if (ENGLISH_FOUR_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (char c : aWordCA) {
                        if (Character.isUpperCase(c)) {
                            mappedLetters2DuplicateKeyValue.put(c, c);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            }
        }
        return nonEnglishPotentialWords;
    }

    // Populate mostSimilaritiesForEachWord
    private void popMostSimilaritiesForEachWord(ArrayList<String> potentialWords)
    {
        mostSimilaritiesForEachWord.clear();
        for (int i = 1; i <= 4; i++) { // 1 letter words, then 2, then 3, then 4
            for (String potentialWord : potentialWords) {
                if (potentialWord.length() == i) {
                    mostSimilarWord(potentialWord);
                }
            }
        }
    }

    // Populate mostSimilaritiesForEachWordMappings
    private void popMostSimilaritiesForEachWordMappings()
    {
        mostSimilaritiesForEachWordMappings.clear();
        for (Pair<String, ArrayList<String>> mostSimilaritiesForAWord : mostSimilaritiesForEachWord) {
            if (mostSimilaritiesForAWord.getKey().length() == 1) { // 1 letter words
                String letterBeingMapped = mostSimilaritiesForAWord.getKey();
                ArrayList<String> newLetterMappings = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (int j = 0; j < mostSimilaritiesForAWord.getValue().size(); j++) {
                    int finalJ = j;
                    tmpArray.add(new ArrayList<Pair<Character, Character>>()
                    {{
                        add(new Pair<>(letterBeingMapped.charAt(0), newLetterMappings.get(finalJ).charAt(0)));
                    }});
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(letterBeingMapped, new ArrayList<>(tmpArray)));
            } else { // 2, 3 and 4 letter words
                char[] wordBeingMapped = mostSimilaritiesForAWord.getKey().toCharArray();
                ArrayList<String> aWord = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (String s : aWord) {
                    ArrayList<Pair<Character, Character>> singleArray = new ArrayList<>(); // All mappings for PE => BE
                    char[] wordBeingMappedTo = s.toCharArray();
                    for (int k = 0; k < wordBeingMapped.length; k++) {
                        if (wordBeingMapped[k] != wordBeingMappedTo[k] && Character.isUpperCase(wordBeingMapped[k])) {
                            singleArray.add(new Pair<>(wordBeingMapped[k], wordBeingMappedTo[k]));
                        }
                    }
                    if (singleArray.size() > 1) {
                        HashMap<Character, Character> tmpMap = new HashMap<>();
                        for (Pair<Character, Character> characterCharacterPair : singleArray) {
                            tmpMap.put(characterCharacterPair.getKey(), characterCharacterPair.getValue());
                        }
                        if (tmpMap.size() < singleArray.size()) {
                            continue;
                        }
                        Set<Character> values = new HashSet<>(tmpMap.values());
                        if (values.size() == singleArray.size()) {
                            tmpArray.add(singleArray);
                        }
                    } else {
                        tmpArray.add(singleArray);
                    }
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(mostSimilaritiesForAWord.getKey(), new ArrayList<>(tmpArray)));
            }
        }
    }

    // Function to remove duplicates from an ArrayList
    private <T> ArrayList<T> removeDuplicates(ArrayList<T> list)
    {
        ArrayList<T> newList = new ArrayList<>();
        for (T element : list) {
            if (!newList.contains(element)) {
                newList.add(element);
            }
        }
        return newList;
    }

    // Populate oneLetterPotentialWordsOccurrences
    private void popOneLetterPotentialWordsOccurrences(ArrayList<String> potentialWords)
    {
        ArrayList<String> oneLetterWords = new ArrayList<>();
        for (String potentialWord : potentialWords) {
            if (potentialWord.length() == 1) {
                oneLetterWords.add(potentialWord);
            }
        }
        HashMap<String, Integer> occurrencesOfOneLetterWords = new HashMap<String, Integer>()
        {{
            for (String oneLetterWord : oneLetterWords) {
                put(oneLetterWord, 0);
            }
        }};
        for (String potentialWord : potentialWords) {
            if (potentialWord.length() == 1) {
                occurrencesOfOneLetterWords.put(potentialWord, occurrencesOfOneLetterWords.get(potentialWord) + 1);
            }
        }
        oneLetterPotentialWordsOccurrences = occurrencesOfOneLetterWords;
    }

    // Reverse the order of an ArrayList containing strings
    private ArrayList<String> reverse(ArrayList<String> list)
    {
        for (int i = 0, j = list.size() - 1; i < j; i++) {
            list.add(i, list.remove(j));
        }
        return list;
    }

    // For a given word, returns the most similar word in ENGLISH_?_LETTER_WORDS
    private void mostSimilarWord(String possibleWord)
    {
        if (possibleWord.length() == 1) {
            if (!ENGLISH_ONE_LETTER_WORDS.contains(possibleWord.toUpperCase())) {
                String oneLetterWordWithMostOccurrences = oneLetterPotentialWordsOccurrences.entrySet().stream().max(Comparator.comparing(Map.Entry::getValue)).get().getKey();
                if (oneLetterWordWithMostOccurrences.equals(possibleWord.toUpperCase())) {
                    mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, ENGLISH_ONE_LETTER_WORDS));
                } else {
                    mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, reverse(ENGLISH_ONE_LETTER_WORDS)));
                }
            } else {
                mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, new ArrayList<>()));
            }
        } else if (possibleWord.length() == 2) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (String word : ENGLISH_TWO_LETTER_WORDS) {
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        } else if (possibleWord.length() == 3) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (String word : ENGLISH_THREE_LETTER_WORDS) {
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        } else if (possibleWord.length() == 4) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (String word : ENGLISH_FOUR_LETTER_WORDS) {
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        }
    }

    // Checks to see is all characters in a string are all lower case
    private boolean allLowerCase(String str)
    {
        char[] charArray = str.toCharArray();
        for (char c : charArray) {
            if (!Character.isLowerCase(c)) {
                return false;
            }
        }
        return true;
    }

    // Checks to see is all characters in a string are all upper case
    private boolean allUpperCase(String str)
    {
        char[] charArray = str.toCharArray();
        for (char c : charArray) {
            if (!Character.isUpperCase(c)) {
                return false;
            }
        }
        return true;
    }

    // Helper for populating mostSimilaritiesForEachWord
    private void genMostSimilarities(String possibleWord, LinkedHashMap<String, Double> similarities)
    {
        ArrayList<String> sortedSimilarWords = new ArrayList<>(sortByValue(similarities));
        if (!allUpperCase(possibleWord)) {
            ArrayList<Integer> lowerCaseIndexes = new ArrayList<>();
            char[] possibleWordCA = possibleWord.toCharArray();
            for (int i = 0; i < possibleWordCA.length; i++) {
                if (Character.isLowerCase(possibleWordCA[i])) {
                    lowerCaseIndexes.add(i);
                }
            }
            ArrayList<String> newSortedList = new ArrayList<>();
            for (String sortedSimilarWord : sortedSimilarWords) {
                boolean toAdd = true;
                for (Integer index : lowerCaseIndexes) {
                    String possibleWordLetter = possibleWord.substring(index, index + 1);
                    String sortedSimilarWordLetter = sortedSimilarWord.substring(index, index + 1);
                    if (!possibleWordLetter.toUpperCase().equals(sortedSimilarWordLetter)) {
                        toAdd = false;
                        break;
                    }
                }
                if (toAdd) {
                    newSortedList.add(sortedSimilarWord);
                }
            }
            mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, newSortedList));
        } else {
            mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, sortedSimilarWords));
        }
    }

    // Sort HashMap by values into descending order
    private Set<String> sortByValue(LinkedHashMap<String, Double> hm)
    {
        //LinkedHashMap preserve the ordering of elements in which they are inserted
        LinkedHashMap<String, Double> reverseSortedMap = new LinkedHashMap<>();
        //Use Comparator.reverseOrder() for reverse ordering
        hm.entrySet().stream().sorted(Map.Entry.comparingByValue(Comparator.reverseOrder())).forEachOrdered(x -> reverseSortedMap.put(x.getKey(), x.getValue()));
        return reverseSortedMap.keySet();
    }

    // Calculates the similarity between two strings
    // 1.0 means the two strings are identical
    // 0.0 means each character in both strings at corresponding indexes are different
    private double similarity(String s1, String s2)
    {
        String longer = s1;
        String shorter = s2;
        if (s1.length() < s2.length()) {
            longer = s2;
            shorter = s1;
        }
        int longerLength = longer.length();
        if (longerLength == 0) {
            return 1.0;
        }
        return (longerLength - editDistance(longer, shorter)) / (double) longerLength;
    }

    // Helper method to calculating the similarity between two strings
    private int editDistance(String s1, String s2)
    {
        s1 = s1.toLowerCase();
        s2 = s2.toLowerCase();
        int[] costs = new int[s2.length() + 1];
        for (int i = 0; i <= s1.length(); i++) {
            int lastValue = i;
            for (int j = 0; j <= s2.length(); j++) {
                if (i == 0) {
                    costs[j] = j;
                } else {
                    if (j > 0) {
                        int newValue = costs[j - 1];
                        if (s1.charAt(i - 1) != s2.charAt(j - 1))
                            newValue = Math.min(Math.min(newValue, lastValue),
                                    costs[j]) + 1;
                        costs[j - 1] = lastValue;
                        lastValue = newValue;
                    }
                }
            }
            if (i > 0) {
                costs[s2.length()] = lastValue;
            }
        }
        return costs[s2.length()];
    }
}
