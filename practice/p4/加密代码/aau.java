package com.aprz;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class aau {

    private static final char[] legalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    public static String a(byte[] arg9) {
        int v4 = arg9.length;
        StringBuffer v5 = new StringBuffer(arg9.length * 3 / 2);
        int v6 = v4 - 3;
        int v2 = 0;
        int v0;
        for(v0 = 0; v0 <= v6; ) {
            int v3 = (arg9[v0] & 255) << 16 | (arg9[v0 + 1] & 255) << 8 | arg9[v0 + 2] & 255;
            v5.append(aau.legalChars[v3 >> 18 & 63]);
            v5.append(aau.legalChars[v3 >> 12 & 63]);
            v5.append(aau.legalChars[v3 >> 6 & 63]);
            v5.append(aau.legalChars[v3 & 63]);
            v3 = v0 + 3;
            v0 = v2 + 1;
            if(v2 >= 14) {
                v5.append("");
                v0 = 0;
            }

            v2 = v0;
            v0= v3;
        }

        if(v0 == -2 + v4) {
            v0 = (arg9[v0 + 1] & 255) << 8 | (arg9[v0] & 255) << 16;
            v5.append(aau.legalChars[v0 >> 18 & 63]);
            v5.append(aau.legalChars[v0 >> 12 & 63]);
            v5.append(aau.legalChars[v0 >> 6 & 63]);
            v5.append("=");
        }
        else if(v0 == -1 + v4) {
            v0 = (arg9[v0] & 255) << 16;
            v5.append(aau.legalChars[v0 >> 18 & 63]);
            v5.append(aau.legalChars[v0 >> 12 & 63]);
            v5.append("==");
        }

        return v5.toString();
    }

    private static int a(char c) {
        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return (c - 'a') + 26;
        }
        if (c >= '0' && c <= '9') {
            return (c - '0') + 26 + 26;
        }
        switch (c) {
            case '+':
                return 62;
            case '/':
                return 63;
            case '=':
                return 0;
            default:
                throw new RuntimeException("unexpected code: " + c);
        }
    }

    public static byte[] a(String str) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            a(str, byteArrayOutputStream);
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            try {
                byteArrayOutputStream.close();
            } catch (IOException e) {
                System.err.println("Error while decoding BASE64: " + e.toString());
            }
            return byteArray;
        } catch (IOException e2) {
            throw new RuntimeException();
        }
    }

    private static void a(String str, OutputStream outputStream) throws IOException {
        int i = 0;
        int length = str.length();
        while (true) {
            if (i < length && str.charAt(i) <= ' ') {
                i++;
            } else if (i != length) {
                int a = (a(str.charAt(i)) << 18) + (a(str.charAt(i + 1)) << 12) + (a(str.charAt(i + 2)) << 6) + a(str.charAt(i + 3));
                outputStream.write((a >> 16) & 255);
                if (str.charAt(i + 2) != '=') {
                    outputStream.write((a >> 8) & 255);
                    if (str.charAt(i + 3) != '=') {
                        outputStream.write(a & 255);
                        i += 4;
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    }




}
