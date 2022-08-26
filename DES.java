import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

public class BBMcrypt {

    public static void main(String[] args) {

        try {
            String operation = args[0];
            String key = "";
            String input = "";
            String output = "";
            String mode = "";

            for (int i = 1; i < 9; i++) {
                if (args[i].equals("-K")) {
                    key = args[i + 1];
                }

                if (args[i].equals("-I")) {
                    input = args[i + 1];
                }

                if (args[i].equals("-O")) {
                    output = args[i + 1];
                }

                if (args[i].equals("-M")) {
                    mode = args[i + 1];
                }
            }

            if (operation.equals("enc") && mode.equals("ECB")) {
                encECB(input, output, key);
            } else if (operation.equals("dec") && mode.equals("ECB")) {
                decECB(input, output, key);
            } else if (operation.equals("enc") && mode.equals("CBC")) {
                encCBC(input, output, key);
            } else if (operation.equals("dec") && mode.equals("CBC")) {
                decCBC(input, output, key);
            } else if (operation.equals("enc") && mode.equals("OFB")) {
                encOFB(input, output, key);
            } else if (operation.equals("dec") && mode.equals("OFB")) {
                decOFB(input, output, key);
            }


        } catch (Exception e) {
            System.out.println("Please give arguments like: enc|dec -K key -I input -O output –M mode");
        }

    }

    public static void encECB(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder plain = new StringBuilder(inputF.nextLine());

            while(plain.toString().length() % 96 != 0) {
                plain = plain.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            System.out.println("Plaintext: " + plain.toString());
            System.out.println("Length of plaintext: " + plain.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);

            ArrayList<String> keys = subkeyGen(decodedKey);

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Encrypted: ");

            for (int block = 0; block < plain.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String plaintextBlock = plain.toString().substring(block * 96, (block + 1) * 96);
                String left = plaintextBlock.substring(0, 48);
                String right = plaintextBlock.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(right);
                    right = xor48(left, scrambleFunction(right, keys.get(i)));
                    left = temp;
                }


                System.out.print(left);
                System.out.print(right);
                out.write(left);
                out.write(right);


            }

            System.out.println();



            out.close();

            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }

    }

    public static void decECB(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder cipher = new StringBuilder(inputF.nextLine());

            while(cipher.toString().length() % 96 != 0) {
                cipher = cipher.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            System.out.println("ciphertext: " + cipher.toString());
            System.out.println("Length of ciphertext: " + cipher.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);

            ArrayList<String> keys = subkeyGen(decodedKey);

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Decrypted: ");

            for (int block = 0; block < cipher.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String ciphertextBlock = cipher.toString().substring(block * 96, (block + 1) * 96);
                String left = ciphertextBlock.substring(0, 48);
                String right = ciphertextBlock.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(left);
                    left = xor48(right, scrambleFunction(left, keys.get(9 - i)));
                    right = temp;
                }


                System.out.print(left);
                System.out.print(right);
                out.write(left);
                out.write(right);


            }

            System.out.println();



            out.close();
            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }
    }

    public static void encCBC(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder plain = new StringBuilder(inputF.nextLine());

            while(plain.toString().length() % 96 != 0) {
                plain = plain.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            System.out.println("Plaintext: " + plain.toString());
            System.out.println("Length of plaintext: " + plain.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);

            ArrayList<String> keys = subkeyGen(decodedKey);
            String IV = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Encrypted: ");

            for (int block = 0; block < plain.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String plaintextBlock = plain.toString().substring(block * 96, (block + 1) * 96);
                plaintextBlock = xor96(IV, plaintextBlock);
                String left = plaintextBlock.substring(0, 48);
                String right = plaintextBlock.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(right);
                    right = xor48(left, scrambleFunction(right, keys.get(i)));
                    left = temp;
                }

                IV = left + right;

                System.out.print(left);
                System.out.print(right);
                out.write(left);
                out.write(right);

            }

            System.out.println();



            out.close();

            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }

    }

    public static void decCBC(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder cipher = new StringBuilder(inputF.nextLine());

            while(cipher.toString().length() % 96 != 0) {
                cipher = cipher.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            System.out.println("ciphertext: " + cipher.toString());
            System.out.println("Length of ciphertext: " + cipher.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);

            ArrayList<String> keys = subkeyGen(decodedKey);
            String IV = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Decrypted: ");

            for (int block = 0; block < cipher.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String ciphertextBlock = cipher.toString().substring(block * 96, (block + 1) * 96);
                String left = ciphertextBlock.substring(0, 48);
                String right = ciphertextBlock.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(left);
                    left = xor48(right, scrambleFunction(left, keys.get(9 - i)));
                    right = temp;
                }

                String plaintext = xor96(IV, left + right);
                IV = ciphertextBlock;

                System.out.print(plaintext);
                out.write(plaintext);

            }

            System.out.println();



            out.close();
            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }
    }

    public static void encOFB(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder plain = new StringBuilder(inputF.nextLine());

            while(plain.toString().length() % 96 != 0) {
                plain = plain.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            String IV = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            System.out.println("Plaintext: " + plain.toString());
            System.out.println("Length of plaintext: " + plain.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);

            ArrayList<String> keys = subkeyGen(decodedKey);

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Encrypted: ");

            for (int block = 0; block < plain.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String plaintextBlock = plain.toString().substring(block * 96, (block + 1) * 96);

                String left = IV.substring(0, 48);
                String right = IV.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(right);
                    right = xor48(left, scrambleFunction(right, keys.get(i)));
                    left = temp;
                }

                IV = left + right;

                System.out.print(xor96(plaintextBlock, left + right));
                out.write(xor96(plaintextBlock, left + right));


            }

            System.out.println();



            out.close();

            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }

    }

    public static void decOFB(String input, String output, String key) {
        try {

            File inputFile = new File(input);
            File outputFile = new File(output);
            File keyFile = new File(key);
            Scanner inputF = new Scanner(inputFile);
            Scanner keyF = new Scanner(keyFile);

            StringBuilder cipher = new StringBuilder(inputF.nextLine());

            while(cipher.toString().length() % 96 != 0) {
                cipher = cipher.append("0");
            }

            StringBuilder base64key = new StringBuilder();
            char[] chars2 = keyF.nextLine().toCharArray();

            for (char aChar : chars2) {
                base64key.append(aChar);
            }

            byte[] decodedBytes = Base64.getDecoder().decode(base64key.toString());
            String decodedKey = new String(decodedBytes);

            System.out.println("Plaintext: " + cipher.toString());
            System.out.println("Length of plaintext: " + cipher.toString().length());
            System.out.println("Base64 Key: " + base64key.toString());
            System.out.println("Key: " + decodedKey);
            String IV = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            ArrayList<String> keys = subkeyGen(decodedKey);

            FileWriter out = new FileWriter(outputFile);

            System.out.print("Decrypted: ");

            for (int block = 0; block < cipher.toString().length() / 96; block++) {
                //System.out.println("block number: " + block);
                String ciphertextBlock = cipher.toString().substring(block * 96, (block + 1) * 96);
                String left = IV.substring(0, 48);
                String right = IV.substring(48, 96);

                for (int i = 0; i < 10; i++) { //this loop is going to be rounds
                    String temp = String.valueOf(right);
                    right = xor48(left, scrambleFunction(right, keys.get(i)));
                    left = temp;
                }

                IV = left + right;
                System.out.print(xor96(ciphertextBlock, left + right));
                out.write(xor96(ciphertextBlock, left + right));


            }

            System.out.println();



            out.close();

            inputF.close();
            keyF.close();

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Please give files that we can find when we search!");
        }

    }

    public static String scrambleFunction(String substring, String subkey) {
        String result = "";
        for (int i = 0; i < 48; i++) { //xor op
            if (substring.charAt(i) == '1' && subkey.charAt(i) == '1') {
                result = result + "0";
            } else if (substring.charAt(i) == '1' && subkey.charAt(i) == '0') {
                result = result + "1";
            } else if (substring.charAt(i) == '0' && subkey.charAt(i) == '1') {
                result = result + "1";
            } else if (substring.charAt(i) == '0' && subkey.charAt(i) == '0') {
                result = result + "0";
            }
        }

        String p1 = String.valueOf(result.charAt(0)) + String.valueOf(result.charAt(1)) + String.valueOf(result.charAt(2)) + String.valueOf(result.charAt(3)) + String.valueOf(result.charAt(4)) + String.valueOf(result.charAt(5));
        String p2 = String.valueOf(result.charAt(6)) + String.valueOf(result.charAt(7)) + String.valueOf(result.charAt(8)) + String.valueOf(result.charAt(9)) + String.valueOf(result.charAt(10)) + String.valueOf(result.charAt(11));
        String p3 = String.valueOf(result.charAt(12)) + String.valueOf(result.charAt(13)) + String.valueOf(result.charAt(14)) + String.valueOf(result.charAt(15)) + String.valueOf(result.charAt(16)) + String.valueOf(result.charAt(17));
        String p4 = String.valueOf(result.charAt(18)) + String.valueOf(result.charAt(19)) + String.valueOf(result.charAt(20)) + String.valueOf(result.charAt(21)) + String.valueOf(result.charAt(22)) + String.valueOf(result.charAt(23));
        String p5 = String.valueOf(result.charAt(24)) + String.valueOf(result.charAt(25)) + String.valueOf(result.charAt(26)) + String.valueOf(result.charAt(27)) + String.valueOf(result.charAt(28)) + String.valueOf(result.charAt(29));
        String p6 = String.valueOf(result.charAt(30)) + String.valueOf(result.charAt(31)) + String.valueOf(result.charAt(32)) + String.valueOf(result.charAt(33)) + String.valueOf(result.charAt(34)) + String.valueOf(result.charAt(35));
        String p7 = String.valueOf(result.charAt(36)) + String.valueOf(result.charAt(37)) + String.valueOf(result.charAt(38)) + String.valueOf(result.charAt(39)) + String.valueOf(result.charAt(40)) + String.valueOf(result.charAt(41));
        String p8 = String.valueOf(result.charAt(42)) + String.valueOf(result.charAt(43)) + String.valueOf(result.charAt(44)) + String.valueOf(result.charAt(45)) + String.valueOf(result.charAt(46)) + String.valueOf(result.charAt(47));


        /*
        System.out.println(substring);
        System.out.println(subkey);
        System.out.println(result);

        System.out.println(p1);
        System.out.println(p2);
        System.out.println(p3);
        System.out.println(p4);
        System.out.println(p5);
        System.out.println(p6);
        System.out.println(p7);
        System.out.println(p8);

         */

        String res48 = sBox(p1) + sBox(p2) + sBox(p3) + sBox(p4) + sBox(p5) + sBox(p6) + sBox(p7) + sBox(p8) + sBox(xor6(p1, p2)) + sBox(xor6(p3, p4)) + sBox(xor6(p5, p6)) + sBox(xor6(p7, p8));

        //System.out.println("res48: " + res48);

        char[] perm = res48.toCharArray();

        for (int i = 0; i < 24; i++) {
            char temp = perm[2 * i];
            perm[2 * i] = perm[(2 * i) + 1];
            perm[(2 * i) + 1] = temp;
        }

        StringBuilder permutatedRes48 = new StringBuilder();
        for (int i = 0; i < 48; i++) {
            permutatedRes48.append(perm[i]);
        }

        //System.out.println("permuteted res48: " + permutatedRes48.toString());
        result = permutatedRes48.toString();
        //System.out.println("result: " + result);

        return result;
    }

    public static String sBox(String input) {
        if (input.equals("000000")) {
            return "0010";
        } else if (input.equals("000010")) {
            return "1100";
        } else if (input.equals("000100")) {
            return "0100";
        } else if (input.equals("000110")) {
            return "0001";
        } else if (input.equals("001000")) {
            return "0111";
        } else if (input.equals("001010")) {
            return "1010";
        } else if (input.equals("001100")) {
            return "1011";
        } else if (input.equals("001110")) {
            return "0110";
        } else if (input.equals("010000")) {
            return "1000";
        } else if (input.equals("010010")) {
            return "0101";
        } else if (input.equals("010100")) {
            return "0011";
        } else if (input.equals("010110")) {
            return "1111";
        } else if (input.equals("011000")) {
            return "1101";
        } else if (input.equals("011010")) {
            return "0000";
        } else if (input.equals("011100")) {
            return "1110";
        } else if (input.equals("011110")) {
            return "1001";
        } else if (input.equals("000001")) {
            return "1110";
        } else if (input.equals("000011")) {
            return "1011";
        } else if (input.equals("000101")) {
            return "0010";
        } else if (input.equals("000111")) {
            return "1100";
        } else if (input.equals("001001")) {
            return "0100";
        } else if (input.equals("001011")) {
            return "0111";
        } else if (input.equals("001101")) {
            return "1101";
        } else if (input.equals("001111")) {
            return "0001";
        } else if (input.equals("010001")) {
            return "0101";
        } else if (input.equals("010011")) {
            return "0000";
        } else if (input.equals("010101")) {
            return "1111";
        } else if (input.equals("010111")) {
            return "1010";
        } else if (input.equals("011001")) {
            return "0011";
        } else if (input.equals("011011")) {
            return "1001";
        } else if (input.equals("011101")) {
            return "1000";
        } else if (input.equals("011111")) {
            return "0110";
        } else if (input.equals("100000")) {
            return "0100";
        } else if (input.equals("100010")) {
            return "0010";
        } else if (input.equals("100100")) {
            return "0001";
        } else if (input.equals("100110")) {
            return "1011";
        } else if (input.equals("101000")) {
            return "1010";
        } else if (input.equals("101010")) {
            return "1101";
        } else if (input.equals("101100")) {
            return "0111";
        } else if (input.equals("101110")) {
            return "1000";
        } else if (input.equals("110000")) {
            return "1111";
        } else if (input.equals("110010")) {
            return "1001";
        } else if (input.equals("110100")) {
            return "1100";
        } else if (input.equals("110110")) {
            return "0101";
        } else if (input.equals("111000")) {
            return "0110";
        } else if (input.equals("111010")) {
            return "0011";
        } else if (input.equals("111100")) {
            return "0000";
        } else if (input.equals("111110")) {
            return "1110";
        } else if (input.equals("100001")) {
            return "1011";
        } else if (input.equals("100011")) {
            return "1000";
        } else if (input.equals("100101")) {
            return "1100";
        } else if (input.equals("100111")) {
            return "0111";
        } else if (input.equals("101001")) {
            return "0001";
        } else if (input.equals("101011")) {
            return "1110";
        } else if (input.equals("101101")) {
            return "0010";
        } else if (input.equals("101111")) {
            return "1101";
        } else if (input.equals("110001")) {
            return "0110";
        } else if (input.equals("110011")) {
            return "1111";
        } else if (input.equals("110101")) {
            return "0000";
        } else if (input.equals("110111")) {
            return "1001";
        } else if (input.equals("111001")) {
            return "1010";
        } else if (input.equals("111011")) {
            return "0100";
        } else if (input.equals("111101")) {
            return "0101";
        } else if (input.equals("111111")) {
            return "0011";
        }
        return "";
    }

    public static String xor6(String p1, String p2) {
        String result = "";
        for (int i = 0; i < 6; i++) { //xor op
            if (p1.charAt(i) == '1' && p2.charAt(i) == '1') {
                result = result + "0";
            } else if (p1.charAt(i) == '1' && p2.charAt(i) == '0') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '1') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '0') {
                result = result + "0";
            }
        }
        return result;
    }

    public static String xor48(String p1, String p2) {
        String result = "";
        for (int i = 0; i < 48; i++) { //xor op
            if (p1.charAt(i) == '1' && p2.charAt(i) == '1') {
                result = result + "0";
            } else if (p1.charAt(i) == '1' && p2.charAt(i) == '0') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '1') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '0') {
                result = result + "0";
            }
        }
        return result;
    }

    public static String xor96(String p1, String p2) {
        String result = "";
        for (int i = 0; i < 96; i++) { //xor op
            if (p1.charAt(i) == '1' && p2.charAt(i) == '1') {
                result = result + "0";
            } else if (p1.charAt(i) == '1' && p2.charAt(i) == '0') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '1') {
                result = result + "1";
            } else if (p1.charAt(i) == '0' && p2.charAt(i) == '0') {
                result = result + "0";
            }
        }
        return result;
    }

    public static ArrayList<String> subkeyGen(String key) {
        ArrayList<String> keys = new ArrayList<String>();

        for (int k = 0; k < 10; k++) { //subkey numbers
            //this two of lines for shifthing
            char firstChar = key.charAt(0);
            String shifted = key.substring(1) + firstChar;
            String permutated = "";

            if (k % 2 == 0) { //key number is even
                // i = 0, 2, 4, 6, 8, ... 94
                for (int i = 0; i < 96; i++) {
                    if (i % 2 == 0) {
                        permutated = permutated + shifted.charAt(i);
                    }
                }
            } else { //key number is odd
                // i = 1, 3, 5, 7, 9, ... 95
                for (int i = 0; i < 96; i++) {
                    if (i % 2 == 1) {
                        permutated = permutated + shifted.charAt(i);
                    }
                }
            }

            keys.add(permutated);
            key = shifted;
        }
        return keys;
    }


}
