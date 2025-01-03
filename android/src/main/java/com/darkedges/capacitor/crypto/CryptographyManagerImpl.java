package com.darkedges.capacitor.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptographyManagerImpl implements CryptographyManager {
    private static final int KEY_SIZE = 256;
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String ENCRYPTION_BLOCK_MODE = "GCM";
    private static final String ENCRYPTION_PADDING = "NoPadding";
    private static final String ENCRYPTION_ALGORITHM = "AES";

    @Override
    public Cipher getInitializedCipherForEncryption(String keyName) throws InvalidKeyException {
        Cipher cipher = getCipher();
        SecretKey secretKey = getOrCreateSecretKey(keyName);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher;
    }

    @Override
    public Cipher getInitializedCipherForDecryption(String keyName, byte[] initializationVector) throws InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = getCipher();
        SecretKey secretKey = getOrCreateSecretKey(keyName);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, initializationVector));
        return cipher;
    }

    @Override
    public EncryptedData encryptData(String plaintext, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return new EncryptedData(ciphertext, cipher.getIV());
    }

    @Override
    public String decryptData(byte[] ciphertext, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException {
        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    private Cipher getCipher() {
        try {
            String transformation = ENCRYPTION_ALGORITHM + "/" + ENCRYPTION_BLOCK_MODE + "/" + ENCRYPTION_PADDING;
            return Cipher.getInstance(transformation);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SecretKey getOrCreateSecretKey(String keyName) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null); // Keystore must be loaded before it can be accessed
            if (keyStore.getKey(keyName, null) != null) {
                return (SecretKey) keyStore.getKey(keyName, null);
            }

            KeyGenParameterSpec.Builder paramsBuilder = new KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
            paramsBuilder.setBlockModes(KeyProperties.BLOCK_MODE_GCM);
            paramsBuilder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE);
            paramsBuilder.setKeySize(KEY_SIZE);
            paramsBuilder.setUserAuthenticationRequired(true);

            KeyGenParameterSpec keyGenParams = paramsBuilder.build();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            keyGenerator.init(keyGenParams);
            return keyGenerator.generateKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
