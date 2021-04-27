package ch.fhnw.krysi.aufgabe2;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class rainbowtable {

    public static void main(String[] args) {

        String gegebenerHashwert = "1d56a37fb6b08aa709fe90e12ca59e12";

        // Erstellen des Zeichensets
        List<String> zeichenSet = generateCompleteCharSet();
        System.out.println("----Kontrolle Zeichenset:----");
        System.out.println("0. Pos Zeichenset: " + zeichenSet.get(0)); // erwartet: 0
        System.out.println("9. Pos Zeichenset: " + zeichenSet.get(9)); // erwartet: 9
        System.out.println("10. Pos Zeichenset: " + zeichenSet.get(10)); // erwartet: a
        System.out.println("35. Pos Zeichenset: " + zeichenSet.get(35)); // erwartet: z
        System.out.println();

        // Erstellen aller Passwörter: letzte 3 Stellen alle aufgefüllt (36*36*36)
        List<String> allPasswordList = generatePassword(zeichenSet);
        // Erstellen der Subliste (nur 2000 Passwörter)
        List<String> passwordList = allPasswordList.subList(0, 2000);
        System.out.println("----Kontrolle Passwort-Liste:----");
        System.out.println("0. Pos passwordList: " + passwordList.get(0)); // erwartet: 00000000
        System.out.println("35. Pos passwordList: " + passwordList.get(35)); // erwartet: 000000z
        System.out.println("36. Pos passwordList: " + passwordList.get(36)); // erwartet: 0000010
        System.out
                .println("1999. Pos passwordList: " + passwordList.get(passwordList.size() - 1));  // erwartet: 0000ijj
        System.out.println("Länge Passwort-Liste: " + passwordList.size()); // erwartet: 2000
        System.out.println();

        System.out.println("----Kontrolle MD5-hashen - DezZahl - reduzieren:----");
        // Kontrolle Stufe 0 0000000 MD5-hashed
        String md5Test = getMD5(passwordList.get(0));
        System.out.println("Stufe 0: 0000000 MD5-gehasht: " + md5Test);

        // Kontrolle Stufe 0 0000000 MD5-hashed als Dezimalzahl
        BigInteger dezTest = getDez(md5Test);
        System.out.println("Stufe 0: Hash in int: " + dezTest);

        // Kontrolle Stufe 0 0000000 MD5-hashed als Dezimalzahl reduziert
        String reductionTest = reduction(dezTest, 0, zeichenSet, 7);
        System.out.println("Stufe 0: Reduzierter Hash: " + reductionTest);

        // Kontrolle Stufe 1 0000000 MD5-hashed
        String md5Test2 = getMD5(reductionTest);
        System.out.println("Stufe 1: Reduzierter Hash wieder gehashed: " + md5Test2);

        // Kontrolle Stufe 1 0000000 MD5-hashed als Dezimalzahl
        BigInteger dezTest2 = getDez(md5Test2);
        System.out.println("Stufe 1: Hash in int: " + dezTest2);

        // Kontrolle Stufe 1 0000000 MD5-hashed als Dezimalzahl reduziert
        String reductionTest2 = reduction(dezTest2, 1, zeichenSet, 7);
        System.out.println("Stufe 1: Reduzierter Hash: " + reductionTest2);

        // Kontrolle Stufe 2 0000000 MD5-hashed
        String md5Test3 = getMD5(reductionTest2);
        System.out.println("Stufe 2: Reduzierter Hash wieder gehashed: " + md5Test3);

        // Kontrolle Stufe 2 0000000 MD5-hashed als Dezimalzahl
        BigInteger dezTest3 = getDez(md5Test3);
        System.out.println("Stufe 2: Hash in int: " + dezTest3);

        // Kontrolle Stufe 2 0000000 MD5-hashed als Dezimalzahl reduziert
        String reductionTest3 = reduction(dezTest3, 2, zeichenSet, 7);
        System.out.println("Stufe 2: Reduzierter Hash: " + reductionTest3);
        System.out.println();

        // Ausführen der ganzen Kette und Ausgeben der ersten und letzten Position der EndPoints-Liste
        List<String> endPoints = rainbowMagic(passwordList, zeichenSet, 7, 2000);
        System.out.println("----Ausgabe 0. und 1999. Position EndPoints-Liste:----");
        System.out.println("endPoint Position 0: " + endPoints.get(0));
        System.out.println("endPoint Position 1999: " + endPoints.get(1999));
        System.out.println();

        System.out.println(
                "----Kontrolle ob der Hash der Stufe 1 genau ab Stufe 1 den Endpoint von 0000000 auf Stufe 2 ergibt:----");
        // Kontrolle Eingabe Hashwert (Stufe 1) - reduzieren - hashen bis "Endpoint" (Stufe 2 reduziert)
        // von Stufe 2 aus
        String hashwert = "12e2feb5a0feccf82a8d4172a3bd51c3";
        hashwert = reduction(getDez(hashwert), 2, zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 2: " + hashwert);

        // von Stufe 1 aus: erwartet: ergibt Endpoint
        String hashwert1 = "12e2feb5a0feccf82a8d4172a3bd51c3";
        hashwert1 = reduction(getDez(hashwert1), 1, zeichenSet, 7);
        hashwert1 = reduction(getDez(getMD5(hashwert1)), 2, zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 1: " + hashwert1);

        // von Stufe 0 aus
        String hashwert2 = "12e2feb5a0feccf82a8d4172a3bd51c3";
        hashwert2 = reduction(getDez(hashwert2), 0, zeichenSet, 7);
        hashwert2 = reduction(getDez(getMD5(hashwert2)), 1, zeichenSet, 7);
        hashwert2 = reduction(getDez(getMD5(hashwert2)), 2, zeichenSet, 7);
        System.out.println("Reduzierter Hashwert ab Stufe 0: " + hashwert2);
        System.out.println("Reduzierter Hashwert von Stufe 2 von 0000000: " + reductionTest3);
        System.out.println();

        // Kontrolle ob, Hash von PW 0000000 von Stufe 1998 ab Stufe 1998 Endpoint ergibt
        String hashPW0Stufe1998 = "f7c9aba38c9a6d58ca7fbe37c33efbbc";
        String endpoint0 = endPoints.get(0);
        System.out.println(
                "----Kontrolle ob der Hash der Stufe 1998 genau ab Stufe 1998 den Endpoint von 0000000 ergibt:----");
        System.out.println("getReducedHash() ab Stufe 1999: " + getReducedHash(hashPW0Stufe1998, 1999, zeichenSet, 7));
        System.out.println("getReducedHash() ab Stufe 1998: " + getReducedHash(hashPW0Stufe1998, 1998, zeichenSet, 7));
        System.out.println("getReducedHash() ab Stufe 1997: " + getReducedHash(hashPW0Stufe1998, 1997, zeichenSet, 7));
        System.out.println("Endpoint von PW 0000000: " + endpoint0);
        System.out.println();

        // Kontrolle, ob Endpunkt von PW 0000000 von Stufe 1998 ab Stufe 1998 in EndPoints-Liste gefunden wird
        System.out.println(
                "findEndPoint() mit Hash von 0000000 Stufe 1998: " + findEndPoint(hashPW0Stufe1998, zeichenSet, 7,
                        endPoints));
        System.out.println("Klartext des Hashes von 0000000 Stufe 1998: " + passwordList
                .get(endPoints.indexOf(findEndPoint(hashPW0Stufe1998, zeichenSet, 7, endPoints))));
        System.out.println();

        // RESULTAT:
        System.out.println(
                "findEndPoint() mit Hash von Aufgabe: " + findEndPoint("1d56a37fb6b08aa709fe90e12ca59e12", zeichenSet,
                        7, endPoints));
        System.out.println("Klartext des Hashes von Aufgabe: " + passwordList
                .get(endPoints.indexOf(findEndPoint("1d56a37fb6b08aa709fe90e12ca59e12", zeichenSet, 7, endPoints))));

        System.out.println("Index of 00000rs: " + passwordList.indexOf("00000rs"));
        System.out.println("Index of igmt8ml: " + endPoints.indexOf("igmt8ml"));



        // Endpoint von 00000rs
        List<String> listOfHashedAndRed_00000rs    = calculateChainFromStartValue("00000rs", zeichenSet, 7);
        System.out.println("Size of listOfHashedAndRed: "+listOfHashedAndRed_00000rs.size());
        String endpointAufgabe = listOfHashedAndRed_00000rs.get(listOfHashedAndRed_00000rs.size()-1);
        System.out.println("Endpoint von 00000rs: " + endpointAufgabe);
        // !! gegebener Hashwert -> Endpoint: igmt8ml
        // !! Endpoint: igmt8ml -> Startpoint: 00000rs
        // !! Endpoint von 00000rs: mi89dgv != igmt8ml
        System.out.println("Enthält listOfHashedAndRed den ggb Hashwert?: "+listOfHashedAndRed_00000rs.contains(gegebenerHashwert)); // !! ggb Hashwert nicht in ListOfHashedAndRed
        System.out.println("Enhält Endpoints-Liste mi89dgv?: "+endPoints.contains("mi89dgv")); // !! mi89dgv nicht in Endpoints-Liste
        // int indexOf2ndEndpoint = endPoints.indexOf("mi89dgv");
        // System.out.println("Index of Endpoint mi89dgv: " + indexOf2ndEndpoint); !! nicht in Endpoint-Liste
        // String startPointOf2ndEndpoint = passwordList.get(indexOf2ndEndpoint);
        // System.out.println("Startpoint of mi89dgv: "+startPointOf2ndEndpoint);
        // System.out.println("Index of Startpoint of mi89dgv: " + passwordList.indexOf(startPointOf2ndEndpoint));
        System.out.println("Ist igmt8ml in Endpoints-Liste enthalten?: "+endPoints.contains("igmt8ml"));
        System.out.println();

        // ToDo
        // fix calculateChainFromStartValue: ergibt von 000000 nicht 545nx4t.
        // Calculate Kette von 00000rs
        // Find gegebener Hashwert in Kette von 00000rs
        // 1 Position vor gegebener Hashwert ist PW
        // finales PW gehashed = gegebener Hashwert


        // Ergibt 00000rs Endpunkt igmt8ml? - Nein!
        // int indexOfGgbHashwert = listOfHashedAndRed.indexOf(gegebenerHashwert); // !! gegebener Hashwert nicht gefunden
        // System.out.println("Index of gegebener Hashwert: "+indexOfGgbHashwert);
        // System.out.println("Reduced before gegebener Hashwert: "+listOfHashedAndRed.get(indexOfGgbHashwert-1));

        // ToDo =wie oben
        // Finde reducedValue right in front of gegebener Hashwert in listOfHashedAndRed: gegebener Hash wird - !! Hashwert nicht in listOfHashedAndRed
        // auf Stufe 1601 gefunden -> Hash wurde auf Stufe 1601 erstellt von reduced von Stufe 1600 aus:
        // listOfHashedAndRed: Hash-reduced-Hash-reduced...: 4000 Einträge (CHECK!): 0-3999, reduced Stufe 1600 auf Position 3200-1 (CHECK by hashing = gegebener Hashwert!).

        // Stand der Dinge
        /*
        Gegebener Hashwert ergibt igmt8ml als Endpoint.
        igmt8ml ist in Endpoints-Liste vorhanden
        igmt8ml als Endpoint ergibt 00000rs als Startpoint.
        ! Kette von 00000rs aus berechnet ergibt Endpoint mi89dgv. Länge der Kette: 4000.
        ! Endpoint mi89dgv ist nicht in Endpoint-Liste. ??? Warum nicht?
        ! Gegebener Hashwert ist nicht in Kette von 00000rs.
         */

//        List<String> sublistEndpoint = endPoints.subList(1001,endPoints.size());
//        System.out.println("Index of igmt8ml in Sublist nach Position 1000: "+ sublistEndpoint.indexOf("igmt8ml")); // igmt8ml kommt nicht 2x in Endpoints-Liste vor
//
//        List<String> listOfHashedAndRed_0000000 = calculateChainFromStartValue(passwordList.get(0), zeichenSet, 7);
//        String endpointOf0000000 = listOfHashedAndRed_0000000.get(
//                listOfHashedAndRed_00000rs.size()-1);
//        System.out.println("Endpoint of listOfHashedAndRed_0000000: "+ endpointOf0000000); // myr8a47 !! sollte 545nx4t ergeben --> calculateChainFromStartValue() ist falsch
//        System.out.println("Ist myr8a47 in Endpoints-Liste enthalten?: "+endPoints.contains("myr8a47"));

        List<String> listOfCalculatedResults = calculatePasswordfromStartValue("00000rs", zeichenSet, 7);
        System.out.println("Gegebener Hashwert ist in Kette von Startwert: "+listOfCalculatedResults.contains(gegebenerHashwert));
        String password = listOfCalculatedResults.get(listOfCalculatedResults.indexOf(gegebenerHashwert)-1);
        System.out.println("Passwort von gegebenem Hashwert: "+password);
        System.out.println("Gehashtes Passwort: "+getMD5(password));
        System.out.println("Gegebener Hashwert: "+gegebenerHashwert);


    }
    //Kette von Startwert
    public static List<String> calculatePasswordfromStartValue(String firstPasswort,List<String> zeichenSet, int laengePW){
        List <String> listOfCalculatedResults = new ArrayList<>();
        String tempPassword = firstPasswort;
        for(int i = 0; i<2000; i++){
            listOfCalculatedResults.add(getMD5(tempPassword));
            listOfCalculatedResults.add(reduction(getDez(getMD5(tempPassword)), i, zeichenSet, laengePW));
            tempPassword = reduction(getDez(getMD5(tempPassword)), i, zeichenSet, laengePW);
        }
        System.out.println("Länge der Liste: " + listOfCalculatedResults.size());
        System.out.println("Letzer Wert in Liste: " + listOfCalculatedResults.get(listOfCalculatedResults.size()-1));

        return listOfCalculatedResults;
    }




    // Kette von gefundenem StartValue aus berechnen
    public static List<String> calculateChainFromStartValue(String startValue, List<String> zeichenSet, int laengePW) {
        List<String> listOfHashesAndRed = new ArrayList<>();
        String hash = startValue;

        for (int j = 0; j < 2000; j++) {
            String reduced;
            hash = getMD5(hash);
            listOfHashesAndRed.add(hash);
            reduced = reduction(getDez(hash), j, zeichenSet, laengePW);
            listOfHashesAndRed.add(reduced);
        }
        System.out.println("Länge der Liste: " + listOfHashesAndRed.size());
        System.out.println("Letzer Wert in Liste: " + listOfHashesAndRed.get(listOfHashesAndRed.size()-1));
        return listOfHashesAndRed;
    }

    // Input: Hash, Aktion: (hashen)-toDez-reduzieren von Stufe 1999-- bis Endpoint gefunden
    public static String findEndPoint(String hash, List<String> zeichenSet, int laengePW, List<String> endPoints) {

        for (int i = 1999; i >= 0; i--) {
            String tempDecryptedHash = getReducedHash(hash, i, zeichenSet, laengePW);
            if (isReducedHashInEndPoints(tempDecryptedHash, endPoints)) {
                System.out.println("Stufe von der aus Endpoint gefunden: "+i);
                return tempDecryptedHash;
            }
        }
        return "Endpoint nicht gefunden!";
    }

    // Input: Endpoint nach Hash-toDez-Reduzieren, Output: ist Endpoint in EndPoints-Liste?
    public static Boolean isReducedHashInEndPoints(String reducedHash, List<String> endPoints) {

        return endPoints.contains(reducedHash);
    }

    // Input: Hashwert, Aktion: (hashen)-toDez-reduzieren ab mitgegebener Stufe, Output: reduzierter Wert
    public static String getReducedHash(String hash, int abStufe, List<String> zeichenSet, int langePW) {
        String reducedHash = "DNW";
        int max = 2000;

        for (int i = abStufe; i < max; i++) {
            if (i == abStufe) {
                reducedHash = reduction(getDez(hash), abStufe, zeichenSet, langePW);
            } else {
                reducedHash = reduction(getDez(getMD5(reducedHash)), i, zeichenSet, langePW);
            }
        }
        return reducedHash;
    }

    // Kette: hashen - hashToDez - reduzieren
    // inkl. Erstellen der EndPoints-Liste
    public static List<String> rainbowMagic(List<String> passwordList, List<String> zeichenSet, int laengePW,
            int stufe) {
        List<String> endPoint = new ArrayList<>();

        for (int i = 0; i < passwordList.size(); i++) {
            String actualPW = passwordList.get(i);
            for (int j = 0; j < stufe; j++) {
                actualPW = reduction(getDez(getMD5(actualPW)), j, zeichenSet, laengePW);
                if (i == 0 && j == 1997) {
                    System.out.println(
                            "----Ausgabe von reduzierter Wert und Hashwert von PW 0000000 ab Stufe 1997 bis Endpoint:----");
                    System.out.println("Reduced nach Stufe 1997: " + actualPW);
                    System.out.println("Hashvalue nach Stufe 1998: " + getMD5(actualPW));
                }
                if (i == 0 && j == 1998) {
                    System.out.println("Reduced nach Stufe 1998: " + actualPW);
                    System.out.println("Hashvalue nach Stufe 1999: " + getMD5(actualPW));
                }
                if (i == 0 && j == 1999) {
                    System.out.println("Reduced nach Stufe 1999: " + actualPW);
                    System.out.println();
                }
            }
            endPoint.add(actualPW);
        }
        return endPoint;
    }

    // ReduktionsFunktion
    public static String reduction(BigInteger hashedDez, int stufe, List<String> zeichenSet, int laengePW) {
        BigInteger numberOfDigits = BigInteger.valueOf(zeichenSet.size());
        BigInteger stufeBig = BigInteger.valueOf(stufe);

        hashedDez = hashedDez.add(stufeBig);

        StringBuilder stringBuilder = new StringBuilder();

        for (int i = 0; i < laengePW; i++) {

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

    // Hex to Dez
    public static BigInteger getDez(String input) {
        BigInteger output = new BigInteger(input, 16);

        return output;
    }

    // MD5-Hashfunktion
    public static String getMD5(String md5Input) {
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
            return md5Output;
        } catch (NoSuchAlgorithmException e) {
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

    // Erstellen der Liste mit 0-9 und a-z
    public static List<String> generateCompleteCharSet() {

        List<String> zahlen = generateNumberSet();
        List<String> buchstaben = generateCharSet();

        List<String> komplett = new ArrayList<>();
        komplett.addAll(zahlen);
        komplett.addAll(buchstaben);

        return komplett;
    }

    // Erstellen der Liste von a-z
    public static List<String> generateCharSet() {
        List<String> buchstaben = new ArrayList<>();

        for (char c = 'a'; c <= 'z'; ++c) {
            buchstaben.add(String.valueOf(c));
        }

        return buchstaben;
    }

    // Erstellen der Liste von 0-9
    public static List<String> generateNumberSet() {
        List<String> zahlen = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            zahlen.add(String.valueOf(i));
        }
        return zahlen;
    }

}

