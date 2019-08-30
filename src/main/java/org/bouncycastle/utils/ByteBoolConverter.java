package org.bouncycastle.utils;

public class ByteBoolConverter {

    public static boolean[] byteToBoolean(byte[] bytes) {
        boolean[] boolArr = new boolean[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++)
            for (int j = 0; j < 8; j++) boolArr[i * 8 + j] = (bytes[i] & (byte) (128 / Math.pow(2, j))) != 0;
        return boolArr;
    }

    public static byte[] booleanToByte(boolean[] bools) {
        byte[] byteArr = new byte[bools.length / 8];
        for (int i = 0; i < byteArr.length; i++) {
            byte b = 0;
            for (int j = 0; j < 8; j++) {
                if (bools[i * 8 + j]) b += Math.pow(2, 7 - j);
            }
            byteArr[i] = b;
        }
        return byteArr;
    }
}
