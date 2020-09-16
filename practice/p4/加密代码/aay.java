package com.aprz;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;

public class aay {

    private static final String IV_HEADER = "G1QW9R5R";
    private static final String KEY_HEADER = "H1T3Q5Q7E90E634A67D901Y5";
    private static final String MCRYPT_TRIPLEDES = "DESede";
    private static final String TRANSFORMATION = "DESede/CBC/PKCS5Padding";
    private static String iv = "vs0ld7w3";
    private static String key = "iufles8787rewjk1qkq9dj76";



    public static String b(String arg4) {
        String v0_2;
        try {
            SecretKey v0_1 = SecretKeyFactory.getInstance("DESede").generateSecret(new DESedeKeySpec(aay.key.getBytes()));
            Cipher v1 = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            v1.init(1, ((Key)v0_1), new IvParameterSpec(aay.iv.getBytes()));
            v0_2 = aau.a(v1.doFinal(arg4.getBytes()));
        }
        catch(Exception v0) {
            v0_2 = "";
        }

        return v0_2;
    }


    public static String a(String str) {
        try {
            SecretKey generateSecret = SecretKeyFactory.getInstance(MCRYPT_TRIPLEDES).generateSecret(new DESedeKeySpec(key.getBytes()));
            Cipher instance = Cipher.getInstance(TRANSFORMATION);
            instance.init(2, generateSecret, new IvParameterSpec(iv.getBytes()));
            return new String(instance.doFinal(aau.a(str)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }



}
