package com.cryptull.naddiaz;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import javax.crypto.KeyAgreement;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * Created by Néstor Álvarez-Díaz (naddiaz) on 27/04/2017.
 *
 * @title Elliptic Curve Diffie-Hellman
 * @date 27/04/2017
 * @author Néstor Álvarez-Díaz
 * @version 1.0.0
 * @apiNote The purpose of this library is make easy the KeyAgreement with ECDH using BouncyCastle as provider
 *
 */

public class ECDH {

    KeyPairGenerator keyGen;
    ECParameterSpec ecSpec;
    private static KeyAgreement uKeyAgree;
    private static KeyPair uKeyPair;
    private static byte[] sharedKey;

    // Add static security provider
    static {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public static final String COM_HELP = "-help";
    public static final String COM_SHOW_CURVES = "-show-curves";
    public static final String COM_SELECT_CURVE = "-curve";
    public static final String COM_GEN_KEYPAIR = "-gen-keypair";
    public static final String COM_SECRET = "-secret";
    public static final String COM_PKU = "-pku";
    public static final String COM_PKR = "-pkr";

    public ECDH() {}

    public static void curves(){
        for(Object curve : Collections.list(ECNamedCurveTable.getNames())){
            System.out.println(curve.toString());
        }
    }

    public void init(String name) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ecSpec = ECNamedCurveTable.getParameterSpec(name);
        keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        keyGen.initialize(ecSpec, new SecureRandom());
    }

    public void keypair() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        uKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        uKeyPair = keyGen.generateKeyPair();
    }

    public void secret(PublicKey rPublicKey, PrivateKey privateKey) throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, UnsupportedEncodingException {
        uKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        uKeyAgree.init(privateKey);
        uKeyAgree.doPhase(rPublicKey, true);
        sharedKey = uKeyAgree.generateSecret();
    }

    public PublicKey publicKey(){
        return uKeyPair.getPublic();
    }

    public PrivateKey privateKey(){
        return uKeyPair.getPrivate();
    }

    public byte[] sharedKey(){
        return sharedKey;
    }

    public static String toBase64(Key key){
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String toBase64(byte[] key){
        return Base64.getEncoder().encodeToString(key);
    }

    public static PublicKey publicFromBase64(String strkey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
                .getInstance("ECDH", "BC")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(strkey)));
    }

    public static PrivateKey privateFromBase64(String strkey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory
                .getInstance("ECDH", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(strkey)));
    }

    public static void main(String[] args) throws Exception {

        Map<String, String> arguments =  parseArguments(args);

        if(arguments.containsKey(COM_HELP) || arguments.size() == 0){
            System.out.println("Sintax: java -jar <JAR_FILE>.jar [-options]");
            System.out.println("Available options:");
            System.out.println("\t -help\n\t\t Print this help message");
            System.out.println("\t -show-curves\n\t\t List of support curves");
            System.out.println("\t -curve=<CURVE_NAME>\n\t\t Select working curve");
            System.out.println("\t -gen-keypair\n\t\t Generating a pair of keys (public and private) and return it in base64 JSON. Need -curve command for selecting the curve");
            System.out.println("\t -pku=<BASE_64_PUBLIC_KEY>\n\t\t Defining the public key in base 64");
            System.out.println("\t -pkr=<BASE_64_PRIVATE_KEY>\n\t\t Defining the private key in base 64");
            System.out.println("\t -secret\n\t\t Requires -pku, -pkr  and -curve options for generating the shared secret and return it in base64 JSON");
        }
        else if(arguments.containsKey(COM_SHOW_CURVES)){
            System.out.println("Available curves:");
            ECDH.curves();
        }
        else if(arguments.containsKey(COM_SELECT_CURVE)){
            if(arguments.containsKey(COM_GEN_KEYPAIR)){
                ECDH ecdh = new ECDH();
                ecdh.init(arguments.get(COM_SELECT_CURVE));
                ecdh.keypair();
                String[] keys = {"public","private"};
                String[] values = {
                    toBase64(ecdh.publicKey()),
                    toBase64(ecdh.privateKey())
                };
                Return(toJSON(keys,values));
            }
            else if(arguments.containsKey(COM_SECRET)
                    && arguments.containsKey(COM_PKU)
                    && arguments.containsKey(COM_PKR)){
                ECDH ecdh = new ECDH();
                ecdh.init(arguments.get(COM_SELECT_CURVE));
                PrivateKey privateKey = privateFromBase64(arguments.get(COM_PKR));
                PublicKey publicKey = publicFromBase64(arguments.get(COM_PKU));
                ecdh.secret(publicKey,privateKey);
                String[] keys = {"secret"};
                String[] values = {
                    toBase64(ecdh.sharedKey())
                };
                Return(toJSON(keys,values));
            }
        }
    }

    // Utils for parse arguments and data
    private static String toJSON(String[] keys, String[] values){
        String r = "{";
        for(int i=0; i<keys.length; i++){
            r += "\"" + keys[i] + "\": \"" + values[i] + "\"";
            if(i<keys.length-1){
                r += ",";
            }
        }
        r += "}";
        return r;
    }

    private static void Return(String ret){
        System.out.print(ret);
    }

    private static HashMap<String, String> parseArguments(String[] args) {
        HashMap<String, String> map = new HashMap<>();
        for (String arg : args) {
            if (arg.contains("=")) {
                map.put(arg.substring(0, arg.indexOf('=')),
                        arg.substring(arg.indexOf('=') + 1));
            }
            else{
                map.put(arg,"true");
            }
        }
        return map;
    }
}
