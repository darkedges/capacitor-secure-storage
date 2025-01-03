package com.darkedges.capacitor.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public interface CryptographyManager {
  /**
   * This method first gets or generates an instance of SecretKey and then initializes the Cipher
   * with the key. The secret key uses Cipher.ENCRYPT_MODE is used.
   */
  Cipher getInitializedCipherForEncryption(String keyName)
    throws InvalidKeyException;

  /**
   * This method first gets or generates an instance of SecretKey and then initializes the Cipher
   * with the key. The secret key uses Cipher.DECRYPT_MODE is used.
   */
  Cipher getInitializedCipherForDecryption(
    String keyName,
    byte[] initializationVector
  ) throws InvalidAlgorithmParameterException, InvalidKeyException;

  /**
   * The Cipher created with getInitializedCipherForEncryption is used here
   */
  EncryptedData encryptData(String plaintext, Cipher cipher)
    throws IllegalBlockSizeException, BadPaddingException;

  /**
   * The Cipher created with getInitializedCipherForDecryption is used here
   */
  String decryptData(byte[] ciphertext, Cipher cipher)
    throws IllegalBlockSizeException, BadPaddingException;
}
