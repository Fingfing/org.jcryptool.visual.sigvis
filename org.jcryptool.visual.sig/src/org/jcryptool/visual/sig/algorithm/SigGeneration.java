// -----BEGIN DISCLAIMER-----
/*******************************************************************************
 * Copyright (c) 2013 JCrypTool Team and Contributors
 * 
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************/
// -----END DISCLAIMER-----
package org.jcryptool.visual.sig.algorithm;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Date;

import org.jcryptool.core.logging.utils.LogUtil;
import org.jcryptool.core.operations.util.ByteArrayUtils;
import org.jcryptool.crypto.keystore.backend.KeyStoreAlias;
import org.jcryptool.crypto.keystore.backend.KeyStoreManager;
import org.jcryptool.crypto.keystore.certificates.CertificateFactory;
import org.jcryptool.crypto.keystore.descriptors.NewEntryDescriptor;
import org.jcryptool.crypto.keystore.descriptors.interfaces.INewEntryDescriptor;
import org.jcryptool.crypto.keystore.keys.KeyType;
import org.jcryptool.visual.sig.SigPlugin;
import org.jcryptool.visual.sig.listener.SignatureEvent;
import org.jcryptool.visual.sig.listener.SignatureListener;
import org.jcryptool.visual.sig.listener.SignatureListenerAdder;

import codec.x509.X509Certificate;

/**
 * Creates a signature for the input with the selected signature methods.
 * 
 * @author Grebe
 */
public class SigGeneration {
    private static PrivateKey k = null;

    /**
     * Old version of SignInput, calls new version of the method
     */
    public static byte[] signInput(String signaturemethod, byte[] input) throws Exception {
        return signInput(signaturemethod, input, null);
    }

    /**
     * This method signs the data stored in Input.java with the signature method selected by the
     * user. It either uses the user selected key or the key given by jctca (stored in Input.java).
     * 
     * @param signaturemethod Chosen signature method to sign the hash.
     * @param input The Data the user selected
     * @return The signature (byte array)
     * @throws Exception
     */
    public static byte[] signInput(String signaturemethod, byte[] input, KeyStoreAlias alias) throws Exception {
        byte[] signature = null; // Stores the signature
        KeyStoreManager ksm = KeyStoreManager.getInstance();
        Input.chosenHash = signaturemethod.replace("withRSA", ""); //$NON-NLS-1$ //$NON-NLS-2$

        if (signaturemethod.contains("ECDSA")) { // Generate a key because there are no ECDSA Keys in the keystore //$NON-NLS-1$
            if (Input.privateKey != null) {
                k = ksm.getPrivateKey(Input.privateKey, KeyStoreManager.KEY_PASSWORD);
                Input.privateKey = null; // Otherwise NullPointerException
            } else {
                // Generate a key pair
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC"); //$NON-NLS-1$
                keyGen.initialize(256, SecureRandom.getInstance("SHA1PRNG")); //$NON-NLS-1$           
                KeyPair pair = keyGen.generateKeyPair();
                k = pair.getPrivate();

                // Save keys in JCT-Keystore
                // Create a descriptor for the publicAlias
                INewEntryDescriptor descriptor = new NewEntryDescriptor("Signatur Demo", "ECDSA", "ECDSA", 256, "1234",
                        keyGen.getProvider().getName(), KeyType.KEYPAIR);
                addKeyPairStatic(descriptor, k, pair.getPublic());
            }
        } else {

            // Check if called by JCT-CA
            if (Input.privateKey != null) { // Use their key
                Input.privateKey.getAliasString();
                k = ksm.getPrivateKey(Input.privateKey, KeyStoreManager.KEY_PASSWORD);
            } else { // Use own Key from given alias
                k = ksm.getPrivateKey(alias, KeyStoreManager.KEY_PASSWORD);
            }
        }

        // Get a signature object using the specified combo and sign the data with the private key
        Signature sig = Signature.getInstance(signaturemethod);
        sig.initSign(k);
        sig.update(input);
        signature = sig.sign();

        if (Input.privateKey != null) {
            String p = null;
            String t = null;
            if (Input.data != null) {
                t = new String(Input.data);
            } else {
                p = Input.path;
            }

            for (SignatureListener lst : SignatureListenerAdder.getListeners()) {
                lst.signaturePerformed(new SignatureEvent(signature, // byte array
                        p, // path
                        t, // direct input
                        new Date(System.currentTimeMillis()), // date time
                        alias, // private key
                        Input.publicKey, // public key
                        Input.chosenHash)); // hash method string
            }
        }

        // Store the generated signature
        Input.signature = signature; // Store the generated original signature
        Input.signatureHex = Input.bytesToHex(signature); // Hex String
        Input.signatureOct = Input.toOctalString(signature, ""); //$NON-NLS-1$
        Input.dataHex = Input.bytesToHex(Input.data);

        return signature;
    }

    /**
     * This method adds a key pair to the JCT-Keystore. Therefore a privateAlias and a publicAlias
     * are created.
     * 
     * @param descriptor A description of the key pair (type, algoName, size, ...).
     * @param privateKey The private Key.
     * @param publicKey The public Key.
     */
    public static void addKeyPairStatic(INewEntryDescriptor descriptor, PrivateKey privateKey, PublicKey publicKey) {
        KeyStoreAlias privateAlias = null;
        KeyStoreAlias publicAlias = null;
        try {
            byte[] hash;
            hash = Hash.hashInput("MD5", descriptor.toString().getBytes());

            // Creates the privateAlias
            privateAlias = new KeyStoreAlias(descriptor.getContactName(), KeyType.KEYPAIR_PRIVATE_KEY,
                    descriptor.getDisplayedName(), descriptor.getKeyLength(), ByteArrayUtils.toHexString(hash),
                    privateKey.getClass().getName());

            // Creates the publicAlias
            publicAlias = new KeyStoreAlias(descriptor.getContactName(), KeyType.KEYPAIR_PUBLIC_KEY,
                    descriptor.getDisplayedName(), descriptor.getKeyLength(), ByteArrayUtils.toHexString(hash),
                    publicKey.getClass().getName());

            X509Certificate jctCertificate = CertificateFactory.createJCrypToolCertificate(publicKey);

            KeyStoreManager.getInstance().addKeyPair(privateKey, jctCertificate,
                    descriptor.getPassword().toCharArray(), privateAlias, publicAlias);

        } catch (Exception ex) {
            LogUtil.logError(SigPlugin.PLUGIN_ID, ex);
        }
    }
}
