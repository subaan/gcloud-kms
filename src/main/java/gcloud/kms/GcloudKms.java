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
import com.google.api.services.cloudkms.v1.model.AsymmetricDecryptRequest;
import com.google.api.services.cloudkms.v1.model.AsymmetricDecryptResponse;
import com.google.api.services.cloudkms.v1.model.Binding;
import com.google.api.services.cloudkms.v1.model.CryptoKey;
import com.google.api.services.cloudkms.v1.model.CryptoKeyVersion;
import com.google.api.services.cloudkms.v1.model.CryptoKeyVersionTemplate;
import com.google.api.services.cloudkms.v1.model.DecryptRequest;
import com.google.api.services.cloudkms.v1.model.DecryptResponse;
import com.google.api.services.cloudkms.v1.model.DestroyCryptoKeyVersionRequest;
import com.google.api.services.cloudkms.v1.model.EncryptRequest;
import com.google.api.services.cloudkms.v1.model.EncryptResponse;
import com.google.api.services.cloudkms.v1.model.KeyRing;
import com.google.api.services.cloudkms.v1.model.Policy;
import com.google.api.services.cloudkms.v1.model.RestoreCryptoKeyVersionRequest;
import com.google.api.services.cloudkms.v1.model.SetIamPolicyRequest;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

/**
 *
 * @author abdul
 */
public class GcloudKms {

    public static void main(String[] args) throws Exception {
        // Create the Cloud KMS client.
//        createKeyRing("appranix-dev-07", "global", "dev-key-ring");
//        createCryptoKey("appranix-dev-07", "global", "dev-key-ring", "crypto-key");

//        addMemberToCryptoKeyPolicy("appranix-dev-07", "global", "dev-key-ring", "crypto-key", "user:abdul@appranix.com", "roles/owner");
//  
//
//        String accessKey = "AKIAJCSC2H3IQ6I4Q3GQ";
//        byte[] b = accessKey.getBytes();
//        byte[] decodedCipherText = encrypt("appranix-dev-07", "global", "dev-key-ring", "crypto-key", b);
//        System.out.println("decodedCipherText: " + decodedCipherText);
//
//        byte[] plainText = decrypt("appranix-dev-07", "global", "dev-key-ring", "crypto-key", decodedCipherText);
//        System.out.println("Plain text: " + new String(plainText));
//        destroyCryptoKeyVersion("appranix-dev-07", "global", "test", "quickstart", "1");
//        restoreCryptoKeyVersion("appranix-dev-07", "global", "test", "quickstart", "1");

//        createAsymmetricKey("asymmetric-signing", "rsa-sign-pss-2048-sha256", "appranix-dev-07", "global", "test", "asymentric-key");
//          addMemberToCryptoKeyPolicy("appranix-dev-07", "global", "test", "asymentric-key", "user:abdul@appranix.com", "roles/owner");
//        createAsymmetricKey("ASYMMETRIC_DECRYPT", "RSA_DECRYPT_OAEP_2048_SHA256", "appranix-dev-07", "global", "test", "asymentric-decrypt-key");
//        addMemberToCryptoKeyPolicy("appranix-dev-07", "global", "test", "asymentric-decrypt-key", "user:abdul@appranix.com", "roles/owner");
        String encryptKeyPath = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", "appranix-dev-07", "global", "test", "asymentric-decrypt-key", "1");
        String decryptKeyPath = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s", "appranix-dev-07", "global", "test", "asymentric-decrypt-key", "1");
//        System.out.println("pub: " + getAsymmetricPublicKey(createAuthorizedClient(), keyPath));
//        
        String accessKey = "AKIAJCSC2H3IQ6I4Q3GQ";
        byte[] b = accessKey.getBytes();
        byte[] decodedCipherText = encryptRSA(b, createAuthorizedClient(), encryptKeyPath);
        System.out.println("decodedCipherText: " + decodedCipherText);
//
        byte[] plainText = decryptRSA(decodedCipherText, createAuthorizedClient(), decryptKeyPath);
        System.out.println("Plain text: " + new String(plainText));
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

    /**
     * Creates a new key ring with the given id.
     *
     * @param projectId
     * @param locationId
     * @param keyRingId
     * @return
     * @throws IOException
     */
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
        CryptoKeyVersionTemplate cryptoKeyVersionTemplate = new CryptoKeyVersionTemplate();
        cryptoKeyVersionTemplate.setAlgorithm("asymmetric-signing");
        cryptoKeyVersionTemplate.setAlgorithm("rsa-sign-pss-2048-sha256");
        cryptoKeyVersionTemplate.setProtectionLevel("software");
        cryptoKey.setVersionTemplate(cryptoKeyVersionTemplate);

//        cryptoKey.setRotationPeriod("30d"); // INTEGER[UNIT], where units can be one of seconds (s), minutes (m), hours (h) or days (d). ex.30d
        // Create the CryptoKey for your project.
        CryptoKey createdKey = kms.projects().locations().keyRings().cryptoKeys()
                .create(parent, cryptoKey)
                .setCryptoKeyId(cryptoKeyId)
                .execute();

        System.out.println(createdKey);
        return createdKey;
    }

    /**
     * Creates a new asymmetric key with the given id.
     */
    public static CryptoKey createAsymmetricKey(String purpose, String algorithm, String projectId, String locationId, String keyRingId,
            String cryptoKeyId)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the location associated with the KeyRing.
        String parent = String.format(
                "projects/%s/locations/%s/keyRings/%s", projectId, locationId, keyRingId);

        // This will allow the API access to the key for encryption and decryption.
        CryptoKey cryptoKey = new CryptoKey();
        cryptoKey.setPurpose(purpose);
        CryptoKeyVersionTemplate cryptoKeyVersionTemplate = new CryptoKeyVersionTemplate();
        cryptoKeyVersionTemplate.setAlgorithm(algorithm);
        cryptoKeyVersionTemplate.setProtectionLevel("software");
        cryptoKey.setVersionTemplate(cryptoKeyVersionTemplate);

//        cryptoKey.setRotationPeriod("30d"); // INTEGER[UNIT], where units can be one of seconds (s), minutes (m), hours (h) or days (d). ex.30d
        // Create the CryptoKey for your project.
        CryptoKey createdKey = kms.projects().locations().keyRings().cryptoKeys()
                .create(parent, cryptoKey)
                .setCryptoKeyId(cryptoKeyId)
                .execute();

        System.out.println(createdKey);
        return createdKey;
    }
    
    /**
     * Creates a new asymmetric key with the given id.
     */
    public static CryptoKey createAsymmetricDecryptKey(String projectId, String locationId, String keyRingId,
            String cryptoKeyId)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the location associated with the KeyRing.
        String parent = String.format(
                "projects/%s/locations/%s/keyRings/%s", projectId, locationId, keyRingId);

        // This will allow the API access to the key for encryption and decryption.
        String purpose = "asymmetric-signing";
        CryptoKey cryptoKey = new CryptoKey();
        cryptoKey.setPurpose(purpose);
        CryptoKeyVersionTemplate cryptoKeyVersionTemplate = new CryptoKeyVersionTemplate();
        cryptoKeyVersionTemplate.setAlgorithm("rsa-sign-pss-2048-sha256");
        cryptoKeyVersionTemplate.setProtectionLevel("software");
        cryptoKey.setVersionTemplate(cryptoKeyVersionTemplate);

//        cryptoKey.setRotationPeriod("30d"); // INTEGER[UNIT], where units can be one of seconds (s), minutes (m), hours (h) or days (d). ex.30d
        // Create the CryptoKey for your project.
        CryptoKey createdKey = kms.projects().locations().keyRings().cryptoKeys()
                .create(parent, cryptoKey)
                .setCryptoKeyId(cryptoKeyId)
                .execute();

        System.out.println(createdKey);
        return createdKey;
    }

    /**
     * Retrieves the public key from a saved asymmetric key pair on Cloud KMS
     *
     * Requires: java.io.StringReader java.security.KeyFactory
     * java.security.PublicKey java.security.Security
     * java.security.spec.X509EncodedKeySpec
     * org.bouncycastle.jce.provider.BouncyCastleProvider
     * org.bouncycastle.util.io.pem.PemReader
     */
    public static PublicKey getAsymmetricPublicKey(CloudKMS client, String keyPath)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        com.google.api.services.cloudkms.v1.model.PublicKey response;

        response = client.projects()
                .locations()
                .keyRings()
                .cryptoKeys()
                .cryptoKeyVersions()
                .getPublicKey(keyPath) //Key version
                .execute();
        PemReader reader = new PemReader(new StringReader(response.getPem()));
        byte[] pem = reader.readPemObject().getContent();
        X509EncodedKeySpec abstractKey = new X509EncodedKeySpec(pem);
        try {
            return KeyFactory.getInstance("RSA", "BC").generatePublic(abstractKey);
        } catch (InvalidKeySpecException e) {
            return KeyFactory.getInstance("ECDSA", "BC").generatePublic(abstractKey);
        }
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

    /**
     * Encrypt data locally using an 'RSA_DECRYPT_OAEP_2048_SHA256' public key
     * retrieved from Cloud KMS
     *
     * Requires: java.security.PublicKey java.security.Security
     * javax.crypto.Cipher org.bouncycastle.jce.provider.BouncyCastleProvider
     */
    public static byte[] encryptRSA(byte[] plaintext, CloudKMS client, String keyPath)
            throws IOException, IllegalBlockSizeException, NoSuchPaddingException,
            InvalidKeySpecException, NoSuchProviderException, BadPaddingException,
            NoSuchAlgorithmException, InvalidKeyException {
        Security.addProvider(new BouncyCastleProvider());
        PublicKey rsaKey = getAsymmetricPublicKey(client, keyPath);

        Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, rsaKey);
        return cipher.doFinal(plaintext);
    }
    
    /**
     * Decrypt a given ciphertext using an 'RSA_DECRYPT_OAEP_2048_SHA256'
     * private key stored on Cloud KMS
     */
    public static byte[] decryptRSA(byte[] ciphertext, CloudKMS client, String keyPath)
            throws IOException {
        AsymmetricDecryptRequest request = new AsymmetricDecryptRequest().encodeCiphertext(ciphertext);
        AsymmetricDecryptResponse response = client.projects()
                .locations()
                .keyRings()
                .cryptoKeys()
                .cryptoKeyVersions()
                .asymmetricDecrypt(keyPath, request)
                .execute();
        return response.decodePlaintext();
    }

    /**
     * Marks the given version of a crypto key to be destroyed at a scheduled
     * future point.
     */
    public static CryptoKeyVersion destroyCryptoKeyVersion(
            String projectId, String locationId, String keyRingId, String cryptoKeyId, String version)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the cryptoKey version
        String cryptoKeyVersion = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
                projectId, locationId, keyRingId, cryptoKeyId, version);

        DestroyCryptoKeyVersionRequest destroyRequest = new DestroyCryptoKeyVersionRequest();

        CryptoKeyVersion destroyed = kms.projects().locations().keyRings().cryptoKeys()
                .cryptoKeyVersions()
                .destroy(cryptoKeyVersion, destroyRequest)
                .execute();

        System.out.println(destroyed);
        return destroyed;
    }

    /**
     * Restores the given version of a crypto key that is currently scheduled
     * for destruction.
     */
    public static CryptoKeyVersion restoreCryptoKeyVersion(
            String projectId, String locationId, String keyRingId, String cryptoKeyId, String version)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the cryptoKey version
        String cryptoKeyVersion = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s/cryptoKeyVersions/%s",
                projectId, locationId, keyRingId, cryptoKeyId, version);

        RestoreCryptoKeyVersionRequest restoreRequest = new RestoreCryptoKeyVersionRequest();

        CryptoKeyVersion restored = kms.projects().locations().keyRings().cryptoKeys()
                .cryptoKeyVersions()
                .restore(cryptoKeyVersion, restoreRequest)
                .execute();

        System.out.println(restored);
        return restored;
    }

    /**
     * Adds the given member to the given key, with the given role.
     *
     * @param projectId The id of the project.
     * @param locationId The location id of the key.
     * @param keyRingId The id of the keyring.
     * @param cryptoKeyId The id of the crypto key.
     * @param member The member to add. Must be in the proper format, eg:
     *
     * allUsers user:$userEmail serviceAccount:$serviceAccountEmail
     *
     * See https://g.co/cloud/kms/docs/reference/rest/v1/Policy#binding for more
     * details.
     * @param role Must be in one of the following formats: roles/[role]
     * organizations/[organizationId]/roles/[role]
     * projects/[projectId]/roles/[role]
     *
     * See https://g.co/cloud/iam/docs/understanding-roles for available values
     * for [role].
     */
    public static Policy addMemberToCryptoKeyPolicy(
            String projectId, String locationId, String keyRingId, String cryptoKeyId, String member,
            String role)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the cryptoKey version
        String cryptoKey = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
                projectId, locationId, keyRingId, cryptoKeyId);

        // Get the current IAM policy
        Policy iamPolicy = getCryptoKeyPolicy(projectId, locationId, keyRingId, cryptoKeyId);

        // Add the new account to it.
        Binding newBinding = new Binding()
                .setRole(role)
                .setMembers(Collections.singletonList(member));
        List<Binding> bindings = iamPolicy.getBindings();
        if (null == bindings) {
            bindings = Collections.singletonList(newBinding);
        } else {
            bindings.add(newBinding);
        }
        iamPolicy.setBindings(bindings);

        // Set the new IAM Policy.
        Policy newIamPolicy = kms.projects().locations().keyRings()
                .cryptoKeys()
                .setIamPolicy(cryptoKey, new SetIamPolicyRequest().setPolicy(iamPolicy))
                .execute();

        System.out.println("Response: " + newIamPolicy);
        return newIamPolicy;
    }

    /**
     * Retrieves the IAM policy for the given crypto key.
     */
    public static Policy getCryptoKeyPolicy(String projectId, String locationId, String keyRingId,
            String cryptoKeyId)
            throws IOException {
        // Create the Cloud KMS client.
        CloudKMS kms = createAuthorizedClient();

        // The resource name of the cryptoKey
        String cryptoKey = String.format(
                "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
                projectId, locationId, keyRingId, cryptoKeyId);

        // Get the current IAM policy and add the new account to it.
        Policy iamPolicy = kms.projects().locations().keyRings().cryptoKeys()
                .getIamPolicy(cryptoKey)
                .execute();

        System.out.println(iamPolicy.getBindings());
        return iamPolicy;
    }

}
