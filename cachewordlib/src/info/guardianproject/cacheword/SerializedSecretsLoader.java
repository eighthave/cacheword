
package info.guardianproject.cacheword;

import java.nio.ByteBuffer;

/**
 * Deserializes secrets, handling upgrading and migration as necessary
 */
public class SerializedSecretsLoader {

    public SerializedSecretsV2 loadSecrets(byte[] secrets) {

        try {
            int version = getVersion(secrets);

            switch (version) {
                case Constants.VERSION_ZERO:
                    return migrateV1toV2(migrateV0toV1(new SerializedSecretsV0(secrets)));
                case Constants.VERSION_ONE:
                    return migrateV1toV2(new SerializedSecretsV1(secrets));
                case Constants.VERSION_TWO:
                    return new SerializedSecretsV2(secrets);
                default:
                    return null;
            }
        } catch (UnsupportedOperationException e) {
            return null;
        }
    }

    public int getVersion(byte[] serialized) throws UnsupportedOperationException {
        ByteBuffer bb = ByteBuffer.wrap(serialized);

        int version = bb.getInt();
        if (version < Constants.VERSION_ZERO || version > Constants.VERSION_MAX) {
            throw new UnsupportedOperationException("Can't load version: " + version);
        }
        return version;
    }

    /**
     * Between V0 and V1 we added the adaptive PBKDF2 iteration count
     */
    private SerializedSecretsV1 migrateV0toV1(SerializedSecretsV0 ss0) {
        // this value used to be in Constants and was assumed for
        // SerializedSecretsV0
        final int old_harcoded_iter_count = 100;

        ss0.parse();
        SerializedSecretsV1 ss1 = new SerializedSecretsV1(Constants.VERSION_ONE,
                old_harcoded_iter_count,
                ss0.salt,
                ss0.iv,
                ss0.ciphertext);

        return ss1;
    }

    /**
     * Between V1 and V2, a flag for the {@link https
     * ://android-developers.blogspot
     * .com/2013/12/changes-to-secretkeyfactory-api-in.html 8-bit
     * PBKDF2WithHmacSHA1 bug} was added
     */
    private SerializedSecretsV2 migrateV1toV2(SerializedSecretsV1 ss1) {
        ss1.parse();
        return new SerializedSecretsV2(
                Constants.KDF_USES_UNKNOWN,
                ss1.pbkdf_iter_count,
                ss1.salt,
                ss1.iv,
                ss1.ciphertext);
    }

}
