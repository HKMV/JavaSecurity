package com.king.security.dh;

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

import org.bouncycastle.util.encoders.Hex;

public class ImoocDH {

	private static String src = "imooc security dh";
	public static void main(String[] args) {
		jdkDH();

	}
	
	public static void jdkDH(){
		try {
			//初始化发送方公钥
			KeyPairGenerator senderKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			senderKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair = senderKeyPairGenerator.generateKeyPair();
			byte[] senderPublicKeyEnc = senderKeyPair.getPublic().getEncoded();//这个发送方公钥发送给接收方
			
			
			//初始化接收方公钥
			KeyFactory receiverKeyFactory = KeyFactory.getInstance("DH");//KeyFactory通过某种规范还原秘钥
			X509EncodedKeySpec receiverX509EncodedKeySpec = new X509EncodedKeySpec(senderPublicKeyEnc);//接收到发送方公钥
			PublicKey receiverPublicKey = receiverKeyFactory.generatePublic(receiverX509EncodedKeySpec);
			DHParameterSpec dhParameterSpec = ((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator = KeyPairGenerator.getInstance("DH");
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			KeyPair receiverKeyPair = receiverKeyPairGenerator.generateKeyPair();
			byte[] receiverPublicKeyEnc = receiverKeyPair.getPublic().getEncoded();//这个接收方公钥发送给发送方
			
			
			//接收方构建本地私钥
			PrivateKey receiverPrivateKey = receiverKeyPair.getPrivate();
			KeyAgreement receiverKeyAgreement = KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(receiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesSecretKey = receiverKeyAgreement.generateSecret("DES");//接收方本地私钥
			
			//发送方构建本地私钥
			KeyFactory senderKeyFactory = KeyFactory.getInstance("DH");
			X509EncodedKeySpec senderX509EncodedKeySpec = new X509EncodedKeySpec(receiverPublicKeyEnc);//接收到接收方公钥
			PublicKey senderPublicKey = senderKeyFactory.generatePublic(senderX509EncodedKeySpec);
			PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
			KeyAgreement senderKeyAgreement = KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderPrivateKey);
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesSecretKey = senderKeyAgreement.generateSecret("DES");//发送方本地私钥
			
			if(receiverDesSecretKey.equals(senderDesSecretKey)){
				System.out.println("双方秘钥相同");
			}
			
			//加密
			Cipher cipher = Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk dh encrypt:"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk dh decrypt:"+new String(result));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
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
	}

}
