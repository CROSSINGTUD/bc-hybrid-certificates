package org.bouncycastle.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class ByteArrayUtils {

    /**
     * Replaces a part in a base byte array with zero-bytes
     *
     * @param base the base array
     * @param replace the part of the base array to replace with zero-bytes
     */
    public static void replaceWithZeros(byte[] base, byte[] replace) {
        List<Byte> baseList = new LinkedList<>();
        for (byte b : base) {
            baseList.add(b);
        }
        List<Byte> sigList = new LinkedList<>();
        for (byte b : replace) {
            sigList.add(b);
        }
        int index = Collections.indexOfSubList(baseList, sigList);
        Arrays.fill(base, index, index + replace.length, (byte) 0);
    }
}
