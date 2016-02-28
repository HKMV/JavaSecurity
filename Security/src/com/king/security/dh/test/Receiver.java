package com.king.security.dh.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class Receiver {
	
	private PublicKey publicKey;//接收方公钥
	private SecretKey receiverDesSecretKey;//本地私钥
	private PublicKey receiverPublicKey;////秘钥工厂生成的临时对象
	private KeyPair receiverKeyPair;
	
	public Receiver() {
		this.publicKey = null;
		this.receiverDesSecretKey = null;
		this.receiverKeyPair = null;
		this.receiverPublicKey = null;
	}
	
	public void initPublicKey(PublicKey senderPublicKey){
		System.out.println("初始化接收方公钥");
		try {
			//初始化接收方公钥
			KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");//KeyFactory通过某种规范还原秘钥
			X509EncodedKeySpec receiverX509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKey.getEncoded());//接收到发送方公钥
			receiverPublicKey = receiverKeyFactory.generatePublic(receiverX509EncodedKeySpec);
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
			publicKey = receiverKeyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void constructPrivateKey(){
		System.out.println("接收方构建本地私钥");
		try {
			//接收方构建本地私钥
			PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
			KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(receiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			receiverDesSecretKey = receiverKeyAgreement.generateSecret("DES");//接收方本地私钥
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public String decrypt(byte[] result){
		System.out.println("解密中...");
		String src = null;
		try {
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.DECRYPT_MODE, receiverDesSecretKey);
			result = cipher.doFinal(result);
			src = new String(result);
			System.out.println("jdk dh decrypt:"+src);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return src;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public SecretKey getReceiverDesSecretKey() {
		return receiverDesSecretKey;
	}
	

}
