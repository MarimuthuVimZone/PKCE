package com.Spring.PKCE;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PKCEUtil {



    private static final SecureRandom secureRandom = new SecureRandom();

    private static final Base64.Encoder base64UrlEncoder = Base64.getUrlEncoder().withoutPadding();

    public static String generateCodeVerifier() {

        byte[] codeVerifierBytes = new byte[32];
        secureRandom.nextBytes(codeVerifierBytes);
        return base64UrlEncoder.encodeToString(codeVerifierBytes);
    }

    public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {

        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);

        return base64UrlEncoder.encodeToString(digest);
    }


    public static void main(String[] args) {
        try {

            String codeVerifier = generateCodeVerifier();

            String codeChallenge = generateCodeChallenge(codeVerifier);


            System.out.println("Code Verifier: " + codeVerifier);
            System.out.println("Code Challenge: " + codeChallenge);
            System.out.println("\nUse these values in your OAuth2 PKCE flow.");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: SHA-256 algorithm not found. " + e.getMessage());
        }
    }
}

