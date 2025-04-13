package org.example;

import java.security.SecureRandom;

public class AES {
    private byte[][] mainKey;
    private final int blockSize = 4;        //4 x 4 bajty
    private int keyWords;
    private int rounds;

    private final int[] sBox = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
            0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
            0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
            0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
            0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
            0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
            0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
            0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
            0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
            0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
            0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
            0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
            0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
            0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
            0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

    private final int[] invSBox = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
            0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
            0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
            0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
            0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
            0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
            0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
            0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
            0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
            0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
            0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
            0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
            0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
            0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
            0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
            0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
            0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
            0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
            0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

    private final int[] Rcon = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
            0x80000000, 0x1b000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000};


    public byte[] encode(byte[] input, byte[] key) {
        int tmpLen = input.length;
        int zeros = 0;
        while (tmpLen != 0) {
            if ((tmpLen - 16) <= 0) {
                zeros = 16 - tmpLen;
                tmpLen = 0;
            } else {
                tmpLen -= 16;
            }
        }

        int mainLen = input.length + zeros + blockSize * blockSize; //padding
        byte[] temp = new byte[mainLen];
        for (int i = 0; i < mainLen; i++) {
            if (i < input.length) {
                temp[i] = input[i];
            } else temp[i] = 0;
        }
        temp[mainLen - 1] = (byte) zeros;

        this.mainKey = generateRoundKeys(key);
        byte[] textPart = new byte[16];
        byte[] result = new byte[mainLen];

        for (int i = 0; i < mainLen; ) {
            for (int j = 0; j < 16; j++) {
                textPart[j] = temp[i];
                i++;
            }
            textPart = encryptBlock(textPart);
            for (int j = i - 16, k = 0; j < i; j++, k++) {
                result[j] = textPart[k];
            }
        }
        return result;
    }

    private byte[][] generateRoundKeys(byte[] key) {
        setRoundsAndKeyWords(key.length);
        byte[][] roundKeys = new byte[blockSize * (rounds + 1)][blockSize];
        for (int i = 0; i < keyWords; i++) {
            for (int j = 0; j < blockSize; j++) {
                roundKeys[i][j] = key[i * blockSize + j];   //"zerowa" runda, z oryginalnym kluczem
            }
        }
        int round = 0;
        int pom = 0;
        for (int i = keyWords; i < blockSize * (rounds + 1); i++) {
            if (i % blockSize == 0) {
                round++;
            }
            if (i % keyWords == 0) {    //sprawdzenie czy została osiągnięta liczba zadanych słów (w zależci od wariantu)
                pom = i - keyWords; //pom = w0
                roundKeys[i] = xorWords(roundKeys[pom], xorWords(subWord(rotWord(roundKeys[pom + 3]), sBox), intToBytes(Rcon[round])));
            } else {      //w razie czego if(i % keyWords != 0)
                roundKeys[i] = xorWords(roundKeys[i - 1], roundKeys[pom++]);
                if (keyWords == 8 & i % 8 == 0) {
                    roundKeys[i] = subWord(roundKeys[i], sBox);
                }
            }
        }
        return roundKeys;
    }

    private byte[] intToBytes(int value) {
        return new byte[]{                                 //dla liczby ujemnej dopisujemy jedynki z lewej strony, a dla dodatniej zera
                (byte) ((value >> 24) & 0xFF),
                (byte) ((value >> 16) & 0xFF),
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
        };
    }

    private void setRoundsAndKeyWords(int keyLength) {
        if (keyLength == 16) {
            this.rounds = 10;
            this.keyWords = 4;
        } else if (keyLength == 24) {
            this.rounds = 12;
            this.keyWords = 6;
        } else if (keyLength == 32) {
            this.rounds = 14;
            this.keyWords = 8;
        } else {
            System.out.println("Invalid key length: " + keyLength);
        }
    }


    private byte[] xorWords(byte[] word1, byte[] word2) {
        if (word1.length == word2.length) {
            byte[] tmp = new byte[word1.length];
            for (int i = 0; i < word1.length; i++) {
                tmp[i] = (byte) (word1[i] ^ word2[i]);
            }
            return tmp;
        } else {
            return null;
        }
    }


    private byte[] rotWord(byte[] word) {
        byte first;
        first = word[0];
        for (int j = 1; j < word.length; j++) {
            word[j - 1] = word[j];
        }
        word[word.length - 1] = first;
        return word;
    }


    private byte[] subWord(byte[] word, int[] box) {
        byte[] workBlock = new byte[blockSize];
        for (int i = 0; i < word.length; i++) {
            workBlock[i] = (byte) (box[(word[i] & 0xff)]); //& 0xff  konwertuje wartość na int, żeby uniknąć ujemnych liczb
        }
        return workBlock;
    }


    public byte[] encryptBlock(byte[] text) {   //SZYFROWANIE
        byte[][] block = new byte[blockSize][blockSize];
        byte[] result = new byte[text.length];
        for (int i = 0; i < text.length; i++) {
            block[i / blockSize][i % blockSize] = text[i];
        }
        block = addRoundKey(block, 0);
        for (int i = 1; i <= rounds; i++) {
            block = subBytes(block, sBox);
            block = shiftRows(block);
            if (i != rounds) {
                block = mixColumns(block);
            }
            block = addRoundKey(block, i);
        }
        for (int i = 0; i < result.length; i++) {
            result[i] = block[i / blockSize][i % blockSize];
        }
        return result;
    }


    private byte[][] addRoundKey(byte[][] block, int roundNb) {
        byte[][] workBlock = new byte[blockSize][blockSize];
        for (int i = 0; i < blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                workBlock[i][j] = (byte) (block[i][j] ^ mainKey[roundNb * blockSize + i][j]);
            }
        }
        return workBlock;
    }


    private byte[][] subBytes(byte[][] block, int[] box) {
        byte[][] workBlock = new byte[blockSize][blockSize];
        for (int i = 0; i < blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                workBlock[i][j] = (byte) (box[(block[i][j] & 0xff)]);
            }
        }
        return workBlock;
    }


    private byte[][] shiftRows(byte[][] block) {
        byte[][] workBlock = new byte[blockSize][blockSize];
        for (int i = 0; i < blockSize; i++) {
            workBlock[0][i] = block[0][i];
        }
        for (int i = 1; i < blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                workBlock[i][j] = block[i][(i + j) % blockSize]; //przesuięcie w prawo o numer wiersza (0-3)
            }
        }
        return workBlock;
    }


    private byte[][] mixColumns(byte[][] blc) {
        byte[][] tmp = new byte[blockSize][blockSize];
        byte b02 = (byte) 0x02;
        byte b03 = (byte) 0x03;
        for (int i = 0; i < blockSize; i++) {
            tmp[0][i] = (byte) (mul(b02, blc[0][i]) ^ mul(b03, blc[1][i]) ^ blc[2][i] ^ blc[3][i]);
            tmp[1][i] = (byte) (blc[0][i] ^ mul(b02, blc[1][i]) ^ mul(b03, blc[2][i]) ^ blc[3][i]);
            tmp[2][i] = (byte) (blc[0][i] ^ blc[1][i] ^ mul(b02, blc[2][i]) ^ mul(b03, blc[3][i]));
            tmp[3][i] = (byte) (mul(b03, blc[0][i]) ^ blc[1][i] ^ blc[2][i] ^ mul(b02, blc[3][i]));
        }
        return tmp;
    }


    private byte mul(byte a, byte b) {
        byte aa = a;
        byte bb = b;
        byte r = 0;
        byte t;
        while (aa != 0) {
            if ((aa & 1) != 0) {
                r = (byte) (r ^ bb);
            }
            t = (byte) (bb & 0x20);
            bb = (byte) (bb << 1);
            if (t != 0) {
                bb = (byte) (bb ^ 0x1b);
            }
            aa = (byte) ((aa & 0xff) >> 1);
        }
        return r;
    }


    public byte[] generateRandomKey(int keyLength) {
        SecureRandom random = new SecureRandom();
        byte[] byteArray = new byte[keyLength];
        random.nextBytes(byteArray);
        return byteArray;
    }

    public byte[] decode(byte[] input, byte[] key) {
        int tempLen = input.length;
        byte[] temp = new byte[tempLen];
        this.mainKey = generateRoundKeys(key);
        byte[] textPart = new byte[16];

        for (int i = 0; i < tempLen; ) {
            for (int j = 0; j < 16; j++) {
                textPart[j] = input[i];
                i++;
            }
            textPart = decryptBlock(textPart);

            for (int j = i - 16, k = 0; j < i; j++, k++) {
                temp[j] = textPart[k];
            }
        }
        int zeros = (temp[temp.length - 1] & 0xff);
        int mainLen = input.length - 16 - zeros;
        byte[] result = new byte[mainLen];
        for (int i = 0; i < mainLen; i++) {
            result[i] = temp[i];
        }

        return result;
    }

    private byte[] decryptBlock(byte[] text) {  //DESZYFROWANIE
        byte[][] block = new byte[blockSize][blockSize];
        byte[] result = new byte[text.length];
        for (int i = 0; i < text.length; i++) {
            block[i / blockSize][i % blockSize] = text[i];
        }
        block = addRoundKey(block, rounds);
        for (int i = rounds - 1; i >= 0; i--) {
            block = subBytes(block, invSBox);
            block = invShiftRows(block);
            block = addRoundKey(block, i);
            if (i != 0) {
                block = invMixColumns(block);
            }
        }
        for (int i = 0; i < result.length; i++) {
            result[i] = block[i / blockSize][i % blockSize];
        }
        return result;
    }

    private byte[][] invMixColumns(byte[][] blc) {
        byte[][] tmp = new byte[blockSize][blockSize];
        byte b14 = (byte) 0x0e;
        byte b11 = (byte) 0x0b;
        byte b13 = (byte) 0x0d;
        byte b09 = (byte) 0x09;
        for (int i = 0; i < blockSize; i++) {
            tmp[0][i] = (byte) (mul(b14, blc[0][i]) ^ mul(b11, blc[1][i]) ^ mul(b13, blc[2][i]) ^ mul(b09, blc[3][i]));
            tmp[1][i] = (byte) (mul(b09, blc[0][i]) ^ mul(b14, blc[1][i]) ^ mul(b11, blc[2][i]) ^ mul(b13, blc[3][i]));
            tmp[2][i] = (byte) (mul(b13, blc[0][i]) ^ mul(b09, blc[1][i]) ^ mul(b14, blc[2][i]) ^ mul(b11, blc[3][i]));
            tmp[3][i] = (byte) (mul(b11, blc[0][i]) ^ mul(b13, blc[1][i]) ^ mul(b09, blc[2][i]) ^ mul(b14, blc[3][i]));
        }
        return tmp;
    }


    private byte[][] invShiftRows(byte[][] block) {
        byte[][] workBlock = new byte[blockSize][blockSize];
        for (int i = 0; i < blockSize; i++) {
            workBlock[0][i] = block[0][i];
        }
        for (int i = 1; i < blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                workBlock[i][j] = block[i][(j - i + blockSize) % blockSize];
            }
        }
        return workBlock;
    }

}