package com.king.security.dh.test;

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

import org.bouncycastle.util.encoders.Hex;

public class Sender {
	
	private PublicKey publicKey;//发送方公钥
	private SecretKey senderDesSecretKey;//本地私钥
	private KeyPair senderKeyPair;
	private PublicKey senderPublicKey;//秘钥工厂生成的临时对象
	
	public Sender(){
		this.publicKey = null;
		this.senderDesSecretKey = null;
		this.senderKeyPair = null;
		this.senderPublicKey = null;
	}
	
	public void initPublicKey(){
		System.out.println("初始化发送方公钥");
		try {
			//初始化发送方公钥
			KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			senderKeyPairGenerator.initialize(512);
			senderKeyPair = senderKeyPairGenerator.generateKeyPair();
			publicKey = senderKeyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void constructPrivateKey(PublicKey receiverPublicKey){
		System.out.println("发送方构建本地私钥");
		try {
			//发送方构建本地私钥
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec senderX509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKey.getEncoded());//接收到接收方公钥
			senderPublicKey = senderKeyFactory.generatePublic(senderX509EncodedKeySpec);
			PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderPrivateKey);
			senderKeyAgreement.doPhase(senderPublicKey, true);
			senderDesSecretKey = senderKeyAgreement.generateSecret("DES");//发送方本地私钥
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public byte[] encrypt(String src){
		System.out.println("加密中...");
		byte[] result = null;
		try {
			//加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesSecretKey);
			result = cipher.doFinal(src.getBytes());
			System.out.println("jdk dh encrypt:"+Hex.toHexString(result));
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
		
		return result;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	public SecretKey getSenderDesSecretKey() {
		return senderDesSecretKey;
	}
	
	

}
