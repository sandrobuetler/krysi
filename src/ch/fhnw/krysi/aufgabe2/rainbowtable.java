package ch.fhnw.krysi.aufgabe2;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLOutput;
import java.util.ArrayList;
import java.util.List;

public class rainbowtable {

    public static void main(String[] args) {

        String gegebenerHashwert = "1d56a37fb6b08aa709fe90e12ca59e12";

        // Erstellen des Zeichensets
        List<String> zeichenSet = generateCompleteCharSet();
        System.out.println("0. Pos Zeichenset: " + zeichenSet.get(0));
        System.out.println("9. Pos Zeichenset: " + zeichenSet.get(9));
        System.out.println("10. Pos Zeichenset: " + zeichenSet.get(10));
        System.out.println("35. Pos Zeichenset: " + zeichenSet.get(35));

        // Erstellen aller Passwörter (2000)
        List<String> allPasswordList = generatePassword(zeichenSet); // letzte 3 Stellen alle aufgefüllt
        List<String> passwordList = allPasswordList.subList(0, 2000);
        System.out.println("0. Pos passwordList: " + passwordList.get(0));
        System.out.println("35. Pos passwordList: " + passwordList.get(35));
        System.out.println("36. Pos passwordList: " + passwordList.get(36));
        System.out.println("1999. Pos passwordList: " + passwordList.get(passwordList.size()-1));
        System.out.println(passwordList.size());

        String md5Test = getMD5(passwordList.get(0));
        System.out.println("0000000 gehasht: "+md5Test);

        System.out.println(Integer.parseInt("a",16));

        BigInteger dezTest = getDez(md5Test);
        System.out.println("hash in int: "+dezTest);

        String reductionTest = reduction(dezTest,0,zeichenSet,7);
        System.out.println("Reduzierter Hash: "+ reductionTest);

        String md5Test2 = getMD5(reductionTest);
        System.out.println("Reduzierter Hash wieder gehashed: "+ md5Test2);

        List<String> endPoints = rainbowMagic(passwordList, zeichenSet, 7, 2000);
        System.out.println ("endPoint Position 0: "+ endPoints.get(0));
        System.out.println ("endPoint Position 2000: "+ endPoints.get(1999));

        BigInteger gegebenerHashToDez = getDez(gegebenerHashwert);
        System.out.println("Gegebener Hash als Dezimal: " + gegebenerHashToDez);

        String gegebenerHashToDezReduziert = reduction(gegebenerHashToDez,1999, zeichenSet,7);
        System.out.println("Gegebener Hash reduziert: " + gegebenerHashToDezReduziert);

        System.out.println("Etwas wurde gefunden: " + endPoints.indexOf(gegebenerHashToDezReduziert));
        //System.out.println(endPoints.get(endPoints.indexOf(gegebenerHashToDezReduziert)));

        String foundEndpoint = comparatorGgbHashwertToEndPoint(getMD5("0000000"),zeichenSet,7, endPoints);
        System.out.println("Gegebener Hash als Endpoint: " + foundEndpoint);

        */
        /*
        String foundEndpoint = new String();
        String hashwert = "29c3eea3f305d6b823f562ac4be35217";

        hashwert = reduction(getDez(hashwert),2,zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 2: "+ hashwert);

        String hashwert1 = "29c3eea3f305d6b823f562ac4be35217";
        hashwert1 = reduction(getDez(hashwert1),1,zeichenSet, 7);
        hashwert1 = reduction(getDez(getMD5(hashwert1)),2,zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 1: "+ hashwert1);

        String hashwert2 = "29c3eea3f305d6b823f562ac4be35217";
        hashwert2 = reduction(getDez(hashwert2),0,zeichenSet, 7);
        hashwert2 = reduction(getDez(getMD5(hashwert2)),1,zeichenSet, 7);
        hashwert2 = reduction(getDez(getMD5(hashwert2)),2,zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 0: "+ hashwert2);
         */

        System.out.println("getDecryptedHash() ab Stufe 1999: "+ getDecryptedHash("d0f342ff295aafcd68f73b471b385878",1999,zeichenSet,7));
        System.out.println("getDecryptedHash() ab Stufe 1998: "+ getDecryptedHash("d0f342ff295aafcd68f73b471b385878",1998,zeichenSet,7));
        System.out.println("getDecryptedHash() ab Stufe 1997: "+ getDecryptedHash("d0f342ff295aafcd68f73b471b385878",1997,zeichenSet,7));
        System.out.println("getDecryptedHash() ab Stufe 1996: "+ getDecryptedHash("d0f342ff295aafcd68f73b471b385878",1996,zeichenSet,7));
        System.out.println("getDecryptedHash() ab Stufe 1995: "+ getDecryptedHash("d0f342ff295aafcd68f73b471b385878",1995,zeichenSet,7));

        System.out.println("findEndPoint() mit Hash von Vogt: "+ findEndPoint("1d56a37fb6b08aa709fe90e12ca59e12",zeichenSet,7,endPoints));
        System.out.println("Klartext des Hashes von Vogt: "+passwordList.get(endPoints.indexOf(findEndPoint("1d56a37fb6b08aa709fe90e12ca59e12",zeichenSet,7,endPoints))));

    }

    public static String findEndPoint(String hash, List<String> zeichenSet, int laengePW, List<String> endPonts){

        for (int i = 1999; i >=0; i--){
            String tempDecryptedHash = getDecryptedHash(hash, i, zeichenSet, laengePW);
            if (isDecryptedHashInEndPoints(tempDecryptedHash, endPonts)){
                return tempDecryptedHash;
            }
        }
        return "Endpoint nicht gefunden!";
    }

    public static Boolean isDecryptedHashInEndPoints(String decryptedHash, List<String> endPoints){

        return endPoints.contains(decryptedHash);

    }

    public static String getDecryptedHash(String hash, int abStufe, List<String> zeichenSet, int langePW){
        String decryptedHash = "DNW";
        int max = 2000;

        for (int i = abStufe; i < max; i++) {
            if (i == abStufe) {
                decryptedHash = reduction(getDez(hash), abStufe, zeichenSet, langePW);
            } else {
                decryptedHash = reduction(getDez(getMD5(decryptedHash)), i, zeichenSet, langePW);
            }
        }
        return decryptedHash;
    }


    // Kette: hashen - hashToDez - reduzieren
   public static List<String> rainbowMagic(List<String> passwordList, List<String> zeichenSet, int laengePW, int stufe) {
        List<String> endPoint = new ArrayList<>();

        for (int i = 0; i < passwordList.size(); i++) {
            String actualPW = passwordList.get(i);
            for (int j = 0; j < stufe; j++) {
                actualPW = reduction(getDez(getMD5(actualPW)), j, zeichenSet, laengePW);
                if (i==0 && j == 2){
                    System.out.println("Nach der 2ten Stufe: "+ actualPW);
                    System.out.println(getMD5(actualPW));
                }
                if(i==0 && j==1998){
                    System.out.println("Reduced 1998 "+actualPW);
                    System.out.println("Hashvalue 1999 "+getMD5(actualPW));
                }
                if(i==0 && j==1999){
                    System.out.println("Reduced 1999 "+actualPW);
                }
            }
            endPoint.add(actualPW);
        }
        return endPoint;
    }


    //ReduktionsFunktion
    public static String reduction(BigInteger hashedDez, int stufe, List<String> zeichenSet, int laengePW){
        BigInteger numberOfDigits = BigInteger.valueOf(zeichenSet.size());
        BigInteger stufeBig = BigInteger.valueOf(stufe);

        hashedDez = hashedDez.add(stufeBig);

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < laengePW; i++){

            //Mod berechnen
            BigInteger ri = hashedDez.mod(numberOfDigits);
            String temp = zeichenSet.get(Integer.parseInt(String.valueOf(ri)));
            stringBuilder.insert(stringBuilder.length(), temp);

            //Div berechnen
            hashedDez = hashedDez.divide(numberOfDigits);

        }
        // stringBuilder: Reihenfolge umkehren
        stringBuilder = stringBuilder.reverse();
        String resultat = stringBuilder.toString();

        return resultat;

    }

    //Hex to Dez
    public static BigInteger getDez(String input){
        BigInteger output = new BigInteger(input,16);

        return output;
    }

    //MD5-Hashfunktion
    public static String getMD5(String md5Input){
        try {
            String md5Output = new String();

            //MD Instanz
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            //Byte Array
            byte[] messageDigest = md5.digest(md5Input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            md5Output = hashtext;
            return md5Output ;
        }

        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    //Generieren aller Passwörter
    public static List<String> generatePassword(List<String> zeichenSet) {
        List<String> passwords = new ArrayList<>();

            String actualPassword;
            for (int i = 6; i >= 0; i--) {
                if (i == 6) {
                    String preZeros = "000000";
                    for (int j = 0; j < zeichenSet.size(); j++) {
                        actualPassword = preZeros + zeichenSet.get(j);
                        passwords.add(actualPassword);
                    }
                }
                if (i == 5) {
                    String preZeros = "00000";
                    for (int j = 1; j < zeichenSet.size(); j++) {
                        for (int k = 0; k < zeichenSet.size(); k++) {
                            actualPassword = preZeros + zeichenSet.get(j) + zeichenSet.get(k);
                            passwords.add(actualPassword);
                        }
                    }
                }
                if (i == 4) {
                    String preZeros = "0000";
                    for (int j = 1; j < zeichenSet.size(); j++) { // j=1; j<2
                        for (int k = 0; k < zeichenSet.size(); k++) { // k=0; k<zeichenSet.size()-16
                            for (int l = 0; l < zeichenSet.size(); l++) { // l=0; l<zeichenSet.size()-16
                                actualPassword = preZeros + zeichenSet.get(j) + zeichenSet.get(k) + zeichenSet.get(l);
                                passwords.add(actualPassword);
                            }
                        }
                    }
                }
            }

        return passwords;
    }


    // Erstellen der Liste von 0-9
    public static List<String> generateNumberSet() {
        List<String> zahlen = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            zahlen.add(String.valueOf(i));
        }
        return zahlen;
    }

    // Erstellen der Liste von a-z
    public static List<String> generateCharSet() {
        List<String> buchstaben = new ArrayList<>();

        for (char c = 'a'; c <= 'z'; ++c) {
            buchstaben.add(String.valueOf(c));
        }

        return buchstaben;
    }

    // Erstellen der Liste mit 0-9 und a-z
    public static List<String> generateCompleteCharSet() {

        List<String> zahlen = generateNumberSet();
        List<String> buchstaben = generateCharSet();

        List<String> komplett = new ArrayList<>();
        komplett.addAll(zahlen);
        komplett.addAll(buchstaben);

        return komplett;
    }

}

