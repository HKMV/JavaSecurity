package com.king.security.elgamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ImoocElGamal {
	
	public static String src = "imooc security ElGamal";

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			//初始化秘钥
			AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
			algorithmParameterGenerator.init(512);
			AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
			DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
			keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey elGamalPublicKey = keyPair.getPublic();
			PrivateKey elGamalPrivateKey = keyPair.getPrivate();
			
			//在cipher初始化的时候出错了
//			//加密
//			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
//			KeyFactory keyFactory = KeyFactory.getInstance("ElGamal","BC");
//			PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
//			Cipher cipher = Cipher.getInstance("ElGamal","BC");
//			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//			byte[] result = cipher.doFinal(src.getBytes());
//			System.out.println("公钥加密，私钥解密--加密:"+Hex.toHexString(result));
//			
//			//解密
//			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
//			keyFactory = KeyFactory.getInstance("ElGamal","BC");
//			PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
//			cipher = Cipher.getInstance("ElGamal","BC");
//			cipher.init(Cipher.DECRYPT_MODE, privateKey);
//			result = cipher.doFinal(result);
//			System.out.println("公钥加密，私钥解密--解密:"+new String(result));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

	}

}
