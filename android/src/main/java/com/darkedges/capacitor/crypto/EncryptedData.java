package com.darkedges.capacitor.crypto;

public record EncryptedData(byte[] ciphertext, byte[] initializationVector) {
}
