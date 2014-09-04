
package info.guardianproject.cacheword;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PassphraseSecretsImpl {

    @SuppressWarnings("unused")
    private static final String TAG = "PassphraseSecretsImpl";

    // used by initialization and change password routines

    /**
     * Derives an encryption key from x_passphrase, then uses this derived key
     * to encrypt x_plaintext. The resulting cipher text, plus meta data
     * (version, salt, iv, @see SerializedSecretsV2) is serialized and returned.
     *
     * @param ctx
     * @param x_passphrase the passphrase used to PBE on plaintext to NOT WIPED
     * @param x_plaintext the plaintext to encrypt NOT WIPED
     * @return instance of {@link SerializedSecretsV2}
     * @throws GeneralSecurityException
     */
    public SerializedSecretsV2 encryptWithPassphrase(Context ctx, char[] x_passphrase,
            byte[] x_plaintext, int pbkdf2_iter_count) throws GeneralSecurityException {
        SecretKeySpec x_passphraseKey = null;
        try {
            byte kdfMode = Constants.KDF_USES_8BIT;
            // if passphrase will not work with PBKDF2WithHmacSHA1 bug in <19
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                for (int i = 0; i < x_passphrase.length; i++)
                    if (x_passphrase[i] > 0xff)
                        kdfMode = Constants.KDF_USES_UNICODE;
            }
            byte[] salt = generateSalt(Constants.PBKDF2_SALT_LEN_BYTES);
            byte[] iv = generateIv(Constants.GCM_IV_LEN_BYTES);
            x_passphraseKey = hashPassphrase(x_passphrase, salt, pbkdf2_iter_count);
            byte[] encryptedSecretKey = encryptSecretKey(x_passphraseKey, iv, x_plaintext);
            SerializedSecretsV2 ss = new SerializedSecretsV2(
                    kdfMode, pbkdf2_iter_count, salt, iv, encryptedSecretKey);
            return ss;
        } finally {
            Wiper.wipe(x_passphraseKey);
        }
    }

    /**
     * Decrypt the secret and returns the plaintext
     *
     * @param x_passphrase NOT WIPED
     * @return the plaintext
     * @throws GeneralSecurityException
     */
    public byte[] decryptWithPassphrase(char[] x_passphrase, SerializedSecretsV2 ss)
            throws GeneralSecurityException {
        byte[] x_plaintext = null;
        SecretKeySpec x_passphraseKey = null;

        try {
            ss.parse();

            byte[] salt = ss.salt;
            byte[] iv = ss.iv;
            byte[] ciphertext = ss.ciphertext;
            int iterations = ss.pbkdf_iter_count;
            // TODO try hashPassphrase8bit if above fails
            switch (ss.passphrase8bit) {
                case Constants.KDF_USES_UNICODE:
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
                        throw new GeneralSecurityException(
                                "Android < 19/4.4.2/KitKat cannot use unicode in KDF!");
                    else
                        x_passphraseKey = hashPassphrase(x_passphrase, salt, iterations);
                    break;
                case Constants.KDF_USES_8BIT:
                    x_passphraseKey = hashPassphrase8bit(x_passphrase, salt, iterations);
                    break;
                case Constants.KDF_USES_UNKNOWN:
                    break;
            }
            x_plaintext = decryptWithKey(x_passphraseKey, iv, ciphertext);

            return x_plaintext;
        } finally {
            Wiper.wipe(x_passphraseKey);
        }
    }

    // used by initialization and verification routines

    /**
     * Hash the password with PBKDF2 at Constants.PBKDF2_ITER_COUNT iterations
     * Does not wipe the password.
     *
     * @param x_password
     * @param salt
     * @return the AES SecretKeySpec containing the hashed password
     * @throws GeneralSecurityException
     */
    public SecretKeySpec hashPassphrase(char[] x_password, byte[] salt, int pbkdf2_iter_count)
            throws GeneralSecurityException {
        PBEKeySpec x_spec = null;
        try {
            x_spec = new PBEKeySpec(x_password, salt, pbkdf2_iter_count,
                    Constants.PBKDF2_KEY_LEN_BITS);
            /*
             * Due to a bug, this key factory will only use lower 8-bits of
             * passphrase chars on older Android versions (API level 18 and
             * lower). It was fixed on KitKat and newer (API level 19 and
             * higher).
             */
            // https://android-developers.blogspot.com/2013/12/changes-to-secretkeyfactory-api-in.html
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            return new SecretKeySpec(factory.generateSecret(x_spec).getEncoded(), "AES");
        } finally {
            Wiper.wipe(x_spec);
        }
    }

    /**
     * Hash the password with PBKDF2 at Constants.PBKDF2_ITER_COUNT iterations.
     * Does not wipe the password. This forces the buggy version before
     * android-19/KitKat for use when compatibility is needed.
     *
     * @param x_password
     * @param salt
     * @return the AES SecretKeySpec containing the hashed password
     * @throws GeneralSecurityException
     */
    public SecretKeySpec hashPassphrase8bit(char[] x_password, byte[] salt, int pbkdf2_iter_count)
            throws GeneralSecurityException {
        PBEKeySpec x_spec = null;
        try {
            x_spec = new PBEKeySpec(x_password, salt, pbkdf2_iter_count,
                    Constants.PBKDF2_KEY_LEN_BITS);

            // https://android-developers.blogspot.com/2013/12/changes-to-secretkeyfactory-api-in.html
            SecretKeyFactory factory;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                /*
                 * Use compatibility key factory -- only uses lower 8-bits of
                 * passphrase chars
                 */
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1And8bit");
            } else {
                /*
                 * Traditional key factory. Will use lower 8-bits of passphrase
                 * chars on older Android versions (API level 18 and lower) and
                 * all available bits on KitKat and newer (API level 19 and
                 * higher).
                 */
                factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            }

            return new SecretKeySpec(factory.generateSecret(x_spec).getEncoded(), "AES");
        } finally {
            Wiper.wipe(x_spec);
        }
    }

    // verification routines: used to unlock secrets

    /**
     * Decrypt with supplied key
     *
     * @param x_passphraseKey NOT WIPED
     * @param iv
     * @param ciphertext
     * @return the plaintext
     * @throws GeneralSecurityException on MAC failure or wrong key
     */
    public byte[] decryptWithKey(SecretKey x_passphraseKey, byte[] iv, byte[] ciphertext)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(ciphertext);
    }

    // initialization routines: creates secrets

    /**
     * Encrypts the data with AES GSM Does not wipe the data nor the key
     *
     * @param x_passphraseKey
     * @param iv
     * @param data
     * @return the encrypted key ciphertext
     * @throws GeneralSecurityException
     */
    public byte[] encryptSecretKey(SecretKey x_passphraseKey, byte[] iv, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // TODO(abel) follow this rabbit hole down and wipe it!
        cipher.init(Cipher.ENCRYPT_MODE, x_passphraseKey, new IvParameterSpec(iv));

        return cipher.doFinal(data);
    }

    @SuppressLint("TrulyRandom")
    public byte[] generateIv(int length) throws NoSuchAlgorithmException {
        byte[] iv = new byte[length];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(iv);
        return iv;
    }

    public byte[] generateSalt(int length) throws NoSuchAlgorithmException {
        byte[] salt = new byte[length];
        SecureRandom.getInstance("SHA1PRNG").nextBytes(salt);
        return salt;
    }

    /**
     * Generate a random AES_KEY_LENGTH bit AES key
     */
    public SecretKey generateSecretKey() {
        try {

            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(Constants.AES_KEY_LEN_BITS);

            return generator.generateKey();

        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
