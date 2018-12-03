/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gcloud.kms;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudkms.v1.CloudKMS;
import com.google.api.services.cloudkms.v1.CloudKMSScopes;
import com.google.api.services.cloudkms.v1.model.CryptoKey;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.api.services.cloudkms.v1.model.KeyRing;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author abdul
 */
public class GcloudKms {

    public static void main(String[] args) throws Exception {
        // Create the Cloud KMS client.
//        createKeyRing("appranix-dev-07", "global", "test2");
//        createCryptoKey("appranix-dev-07", "global", "test2", "crpto-key");

        String accessKey = "AKIAJCSC2H3IQ6I4Q3GQ";
        byte[] b = accessKey.getBytes();
        byte[] decodedCipherText = encrypt("appranix-dev-07", "global", "test2", "crpto-key", b);
        System.out.println("decodedCipherText: " + decodedCipherText);
        
        byte[] plainText = decrypt("appranix-dev-07", "global", "test2", "crpto-key", decodedCipherText);
        System.out.println("Plain text: "+new String(plainText));

    }

    /**
     * Creates an authorized CloudKMS client service using Application Default
     * Credentials.
     *
     * @return an authorized CloudKMS client
     * @throws IOException if there's an error getting the default credentials.
     */
    public static CloudKMS createAuthorizedClient() throws IOException {
        // Create the credential
        HttpTransport transport = new NetHttpTransport();
        JsonFactory jsonFactory = new JacksonFactory();
        // Authorize the client using Application Default Credentials
        // @see https://g.co/dv/identity/protocols/application-default-credentials
//    GoogleCredential credential = AppEngineCreden.getApplicationDefault();
        GoogleCredential credential = GoogleCredential.getApplicationDefault(transport, jsonFactory);

        // Depending on the environment that provides the default credentials (e.g. Compute Engine, App
        // Engine), the credentials may require us to specify the scopes we need explicitly.
        // Check for this case, and inject the scope if required.
        if (credential.createScopedRequired()) {
            credential = credential.createScoped(CloudKMSScopes.all());
        }

        return new CloudKMS.Builder(transport, jsonFactory, credential)
                .setApplicationName("CloudKMS snippets")
                .build();
    }

//    /**
// * Creates a new key ring with the given id.
// */
    public static KeyRing createKeyRing(String projectId, String locationId, String keyRingId)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the location associated with the KeyRing.
        String parent = String.format("projects/%s/locations/%s", projectId, locationId);
        // Create the KeyRing for your project.
        KeyRing keyring = kms.projects().locations().keyRings()
                .create(parent, new KeyRing())
                .setKeyRingId(keyRingId)
                .execute();

        System.out.println(keyring);
        return keyring;
    }

    /**
     * Creates a new crypto key with the given id.
     */
    public static CryptoKey createCryptoKey(String projectId, String locationId, String keyRingId,
            String cryptoKeyId)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the location associated with the KeyRing.
        String parent = String.format(
                "projects/%s/locations/%s/keyRings/%s", projectId, locationId, keyRingId);

        // This will allow the API access to the key for encryption and decryption.
        String purpose = "ENCRYPT_DECRYPT";
        CryptoKey cryptoKey = new CryptoKey();
        cryptoKey.setPurpose(purpose);

        // Create the CryptoKey for your project.
        CryptoKey createdKey = kms.projects().locations().keyRings().cryptoKeys()
                .create(parent, cryptoKey)
                .setCryptoKeyId(cryptoKeyId)
                .execute();

        System.out.println(createdKey);
        return createdKey;
    }

    /**
     * Encrypts the given plaintext using the specified crypto key.
     */
    public static byte[] encrypt(
            String projectId, String locationId, String keyRingId, String cryptoKeyId, byte[] plaintext)
            throws IOException {
        // The resource name of the cryptoKey
        String resourceName = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
                projectId, locationId, keyRingId, cryptoKeyId);

        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        EncryptRequest request = new EncryptRequest().encodePlaintext(plaintext);
        EncryptResponse response = kms.projects().locations().keyRings().cryptoKeys()
                .encrypt(resourceName, request)
                .execute();

        return response.decodeCiphertext();
    }

    /**
     * Decrypts the provided ciphertext with the specified crypto key.
     */
    public static byte[] decrypt(String projectId, String locationId, String keyRingId,
            String cryptoKeyId, byte[] ciphertext)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the cryptoKey
        String cryptoKeyName = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
                projectId, locationId, keyRingId, cryptoKeyId);

        DecryptRequest request = new DecryptRequest().encodeCiphertext(ciphertext);
        DecryptResponse response = kms.projects().locations().keyRings().cryptoKeys()
                .decrypt(cryptoKeyName, request)
                .execute();

        return response.decodePlaintext();
    }

}
