package com.king.security.aes;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ImoocAES {
	
	private static String src = "imooc security aes";
	
	public static void main(String[] args) {
		jdkAES();
		bcAES();

	}
	
	public static void jdkAES(){
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			//只能使用长度128
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
//			System.out.println(secretKey.hashCode());
			
			//key转换
			//这里的转换也是没有意义的
			Key key = new SecretKeySpec(bytesKey, "AES");
//			System.out.println(key.hashCode());
			
			//加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk aes encrypt:"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			result = cipher.doFinal(result);
			System.out.println("jdk aes decrypt:"+new String(result));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void bcAES(){
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
			System.out.println(keyGenerator.getProvider());
			//bc中长度192,256会报错
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			System.out.println(secretKey.hashCode());
			
			//key转换
			//这里的转换也是没有意义的
			Key key = new SecretKeySpec(bytesKey, "AES");
			System.out.println(key.hashCode());
			
			//加密
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding","BC");//在这里同样要手动添加provider
			System.out.println(cipher.getProvider());
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc aes encrypt:"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			result = cipher.doFinal(result);
			System.out.println("bc aes decrypt:"+new String(result));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
