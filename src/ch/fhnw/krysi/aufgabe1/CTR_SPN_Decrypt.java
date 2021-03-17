package ch.fhnw.krysi.aufgabe1;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class CTR_SPN_Decrypt {

    public static void main(String[] args) throws IOException {

        String chiffretext = ReadTXTFile("src/ch/fhnw/krysi/aufgabe1/TextFiles/CTR_SPN/chiffre.txt");
        String chiffreSchluessel = ReadTXTFile("src/ch/fhnw/krysi/aufgabe1/TextFiles/CTR_SPN/chiffreSchluessel.txt");

        /*
        String yMinus1 = getYMinus1(chiffretext);
        int yMinus1Int = BinToInt(yMinus1);
        String yMinus1Plus1 = IntToBin(yMinus1Int + 1);
         */

        String[] yMinus1Set = YMinus1Set(chiffretext);

        String[] unterteilterChiffretext = UnterteilterChiffreText(chiffretext);

        String[] schluesselset_SPN = Schluesselberechnung(chiffreSchluessel);
        String[] entschluesselset_SPN = Entschluesselberechnung(schluesselset_SPN);

        System.out.println("Chiffretext: "+chiffretext);
        System.out.println("Entschlüsselset K'0: "+ entschluesselset_SPN[0]);

        // ACHTUNG unterteilterChiffretext[0] ist nicht befüllt, siehe Methode UnterteilterChiffretext
        String decryptX0 = Decrypt(entschluesselset_SPN, yMinus1Set[0], unterteilterChiffretext[1]);
        System.out.println("Resultat für Decrypted X0: "+decryptX0);

        String decryptX1 = Decrypt(entschluesselset_SPN, yMinus1Set[1], unterteilterChiffretext[2]);
        System.out.println("Resultat für Decrypted X1: "+decryptX1);

        String decryptX2 = Decrypt(entschluesselset_SPN, yMinus1Set[2], unterteilterChiffretext[3]);
        System.out.println("Resultat für Decrypted X2: "+decryptX2);

        String decryptX3 = Decrypt(entschluesselset_SPN, yMinus1Set[3], unterteilterChiffretext[4]);
        System.out.println("Resultat für Decrypted X3: "+decryptX3);

        String decryptX4 = Decrypt(entschluesselset_SPN, yMinus1Set[4], unterteilterChiffretext[5]);
        System.out.println("Resultat für Decrypted X4: "+decryptX4);

        String decryptX5 = Decrypt(entschluesselset_SPN, yMinus1Set[5], unterteilterChiffretext[6]);
        System.out.println("Resultat für Decrypted X5: "+decryptX5);

        String decryptX6 = Decrypt(entschluesselset_SPN, yMinus1Set[6], unterteilterChiffretext[7]);
        System.out.println("Resultat für Decrypted X6: "+decryptX6);

        String finalDecrypted = decryptX0+decryptX1+decryptX3+decryptX4+decryptX5+decryptX6;

        for (int i = 0; i < yMinus1Set.length; i++) {
            System.out.println("Y Minus 1 Set Position "+i+" hat den Wert: "+yMinus1Set[i]);
        }

        System.out.println("Tadaaaaaaaaaaa: "+finalDecrypted);
    }

    private static String Decrypt(String[] entschluesselset_SPN, String yMinus1, String unterteilterChiffretext) {

        // 1) k'0
        String afterWeissschritt = multipleXOR(yMinus1, entschluesselset_SPN[0]);
        //System.out.println("Nach Weissschritt: " + afterWeissschritt);

        // 2) 1_2a
        String after1stSBox = SBoxInvers(afterWeissschritt);
        //System.out.println("Nach 1st SBOXInvers: "+ after1stSBox);

        // 2) 1_2b
        String after1stBP = BitPermutation(after1stSBox);
       //System.out.println("Nach 1st BP: "+ after1stBP);

        // 2) 1_2c mit k'1
        String after1stXOR = multipleXOR(after1stBP, entschluesselset_SPN[1]);
        //System.out.println("Nach 1st XOR: "+ after1stXOR);

        // 2) 2_2a
        String after2ndSBox = SBoxInvers(after1stXOR);
        //System.out.println("Nach 2nd SBOXInvers: "+ after2ndSBox);

        // 2) 2_2b
        String after2ndBP = BitPermutation(after2ndSBox);
        //System.out.println("Nach 2nd BP: "+ after2ndBP);

        // 2) 2_2c mit k'2
        String after2ndXOR = multipleXOR(after2ndBP, entschluesselset_SPN[2]);
        //System.out.println("Nach 2nd XOR: "+ after2ndXOR);

        // 2) 3_2a
        String after3rdSBox = SBoxInvers(after2ndXOR);
        //System.out.println("Nach 3rd SBOXInvers: "+ after3rdSBox);

        // 2) 3_2b
        String after3rdBP = BitPermutation(after3rdSBox);
        //System.out.println("Nach 3rd BP: "+ after3rdBP);

        // 2) 3_2c mit k'3
        String after3rdXOR = multipleXOR(after3rdBP, entschluesselset_SPN[3]);
        //System.out.println("Nach 3rd XOR: "+ after3rdXOR);

        // 3) 3a
        String afterlastSBox = SBoxInvers(after3rdXOR);
        //System.out.println("Nach last SBOXInvers: "+ afterlastSBox);

        // 3) 3c mit k'4
        String afterlastXOR = multipleXOR(afterlastSBox, entschluesselset_SPN[4]);
        System.out.println("Nach last XOR: "+ afterlastXOR);

        // After last XOR from SPN -> XOR with Y0 (unterteilterChiffretext)
        String result = multipleXOR(afterlastXOR, unterteilterChiffretext);

        return result;


    }

    private static String[] UnterteilterChiffreText(String chiffretext) {
        String[] unterteilterChiffretext = new String[8];

        for (int i = 1; i < 8; i++) {
            unterteilterChiffretext[i] = chiffretext.substring(16*i,16*i+16);
            System.out.println("Neuer Chiffretext "+i+" : "+unterteilterChiffretext[i]);
        }

        return unterteilterChiffretext;
    }

    private static String[] YMinus1Set(String chiffretext) {
        String[] yMinus1Set = new String[7];

        for (int i = 0; i < yMinus1Set.length; i++) {
            yMinus1Set[i] = IntToBin(BinToInt(getYMinus1(chiffretext))+i);
        }
        for (int i = 0; i < yMinus1Set.length; i++) {
            System.out.println("Y Minus 1 Set Position "+i+" hat Zahlenwert "+BinToInt(yMinus1Set[i]));
        }

        return yMinus1Set;
    }

    private static String[] Entschluesselberechnung(String[] schluesselset) {
        String[] entschluesselset = new String[5];

        entschluesselset[0] = schluesselset[4];
        entschluesselset[1] = BitPermutation(schluesselset[3]);
        entschluesselset[2] = BitPermutation(schluesselset[2]);
        entschluesselset[3] = BitPermutation(schluesselset[1]);
        entschluesselset[4] = schluesselset[0];

        for (int i = 0; i < 5; i++) {
            System.out.println("Entschlüssel Schlüssel"+i+": "+entschluesselset[i]);
        }

        return entschluesselset;
    }

    private static String[] Schluesselberechnung(String schluesseltext) {
        String[] schluesselset = new String[5];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j <= 15; j++) {
                if(j == 0){
                    schluesselset[i] = Character.toString(schluesseltext.charAt(j+(i*4)));
                }else {
                    schluesselset[i] = schluesselset[i] + schluesseltext.charAt(j + (i * 4));
                }
            }
        }

        for (int i = 0; i < 5; i++) {
            System.out.println("Schlüssel"+i+": "+schluesselset[i]);
        }

        return schluesselset;

    }

    public static String SBoxInvers(String toSBox){
        String afterSbox = null;

        HashMap<String, String> SBox = new HashMap<String, String>();
        SBox.put("0000", "1110"); //0
        SBox.put("0001", "0100"); //1
        SBox.put("0010", "1101"); //2
        SBox.put("0011", "0001"); //3
        SBox.put("0100", "0010"); //4
        SBox.put("0101", "1111"); //5
        SBox.put("0110", "1011"); //6
        SBox.put("0111", "1000"); //7
        SBox.put("1000", "0011"); //8
        SBox.put("1001", "1010"); //9
        SBox.put("1010", "0110"); //10
        SBox.put("1011", "1100"); //11
        SBox.put("1100", "0101"); //12
        SBox.put("1101", "1001"); //13
        SBox.put("1110", "0000"); //14
        SBox.put("1111", "0111"); //15


        int numberOfPackages = toSBox.length()/4;
        for (int i = 0; i < numberOfPackages; i++) {
            String output = null;
            String input = Character.toString(toSBox.charAt(i*4));
            input = input +  toSBox.charAt((i*4)+1);
            input = input +  toSBox.charAt(i*4+2);
            input = input +  toSBox.charAt(i*4+3);
            System.out.println("Input nach dem Durchgang Nummer "+i+": "+input);
            for (Map.Entry<String, String> entry : SBox.entrySet()){
                if (entry.getValue().equals(input)){
                    output = entry.getKey();
                }
            }
            if(afterSbox != null){
                afterSbox = afterSbox + output;
            }else{
                afterSbox = output;
            }
        }

        return afterSbox;
    }

    public static String BitPermutation(String toBP){

        HashMap<Integer, Integer> BP = new HashMap<Integer, Integer>();
        BP.put(0,0);
        BP.put(1,4);
        BP.put(2,8);
        BP.put(3,12);
        BP.put(4,1);
        BP.put(5,5);
        BP.put(6,9);
        BP.put(7,13);
        BP.put(8,2);
        BP.put(9,6);
        BP.put(10,10);
        BP.put(11,14);
        BP.put(12,3);
        BP.put(13,7);
        BP.put(14,11);
        BP.put(15,15);

        int numberOfBits = toBP.length();
        //ACHTUNG HARDCODED 16 -> Muss auf die entprechende Textlänge angepasst werden!
        String[] newPosition = new String[16];
        for (int i = 0; i < numberOfBits; i++) {
            String digit = Character.toString(toBP.charAt(i));
            newPosition[BP.get(i)] = digit;
        }

        String afterBP = null;
        for (int i = 0; i < newPosition.length; i++) {
            if(i==0){
                afterBP = newPosition[i];
            }else{
                afterBP = afterBP + newPosition[i];
            }
        }

        return afterBP;
    }

    public static String multipleXOR(String a, String b){
        System.out.println("XOR WERT A: "+a);
        System.out.println("XOR WERT B: "+b);
        String returnString = null;

        //ACHTUNG HARDCODED 16 -> Muss auf die entprechende Textlänge angepasst werden!
        for (int i = 0; i < 16; i++) {
            if(a.charAt(i) == b.charAt(i)) {
               if(i == 0){
                    returnString = "0";
                }else {
                    returnString = returnString + "0";
                }
            }else{
                if(i == 0){
                    returnString = "1";
                }else {
                    returnString = returnString + "1";
                }
            }
        }
        return returnString;
    }



    public static String xOr(String a, String b){
        if(a == b){
            return "0";
        }else{
            return "1";
        }
    }

    public static String ReadTXTFile(String path) throws IOException {

        String chiffre = new String(Files.readAllBytes(Paths.get(path)));
        System.out.println("Eingelesen: " + chiffre);

        return chiffre;
    }

    public static Integer BinToInt(String binaerZahl){
        int integerNumber = Integer.parseInt(binaerZahl,2);

        System.out.println(binaerZahl+" Wurde umgewandelt in "+String.valueOf(integerNumber));

        return integerNumber;
    }

    public static String IntToBin(int dezimalZahl){
        Integer[] binaryNumber = new Integer[16];
        System.out.println("Dezimalzahl: "+dezimalZahl);

        int index = 0;
        while (dezimalZahl > 0){
        binaryNumber[index++] = dezimalZahl%2;
        dezimalZahl = dezimalZahl/2;
        }
        for (int i = 0; i < binaryNumber.length; i++) {
            System.out.println("Index Nummer "+i+" hat wert "+binaryNumber[i]);
        }

        String binaryString = null;
        for (int i = 15; i >= 0; i--) {
            if(i == 15){
                if(binaryNumber[i] == null){
                    binaryString = "0";
                }else if (binaryNumber[i] == 0){
                    binaryString = "0";
                }else if (binaryNumber[i] == 1){
                    binaryString = "1";
                }
            }else if(binaryNumber[i] == null){
                binaryString = binaryString + "0";
            }else if (binaryNumber[i] == 0){
                binaryString = binaryString + "0";
            }else if (binaryNumber[i] == 1){
                binaryString = binaryString + "1";
            }
        }
        return binaryString;
    }

    public static String getYMinus1(String chiffretext){
        String yMinus1 = chiffretext.substring(0,16);
        System.out.println("y-1: "+yMinus1);
        return yMinus1;
    }

}
