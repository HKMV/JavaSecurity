package com.king.security.des;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ImoocDES {
	
	private static String src = "imooc security des";


	
	public static void main(String[] args) {
		jdkDES();
		bcDES();
		kingDES();

	}
	
	public static void jdkDES(){
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56);//初始化，秘钥长度为56
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();

			
//			System.out.println(secretKey.hashCode());
			
			//key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			Key convertSecretKey = keyFactory.generateSecret(desKeySpec);
			
//			System.out.println(convertSecretKey.hashCode());
//			System.out.println(secretKey.equals(convertSecretKey));
			
			/**
			 * 通过打印可以知道secretKey和convertSecretKey是同一个对象，
			 * 那么第二步key的转换可以说是没有意义
			 * 
			 */
			
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//算法/工作方式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk des encrypt :"+Hex.toHexString(result));
			
//			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//			result = cipher.doFinal(src.getBytes());
//			System.out.println("jdk des encrypt :"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk des decrypt :"+new String(result));
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void bcDES(){
		//添加provider
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			//生成key
			//在这里要指定provider为bc，不然provoder还是sunJCE			
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
//			System.out.println(keyGenerator.getProvider());			
			keyGenerator.init(56);//初始化，秘钥长度为56
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			Key convertSecretKey = keyFactory.generateSecret(desKeySpec);
			
			
			//加密
			//在这里要指定provider为bc，不然provoder还是sunJCE
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding","BC");//算法/工作方式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc des encrypt :"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc des decrypt :"+new String(result));
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * 自己改写步骤
	 */
	public static void kingDES(){
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56);//初始化，秘钥长度为56
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			System.out.println("bytesKey:"+Hex.toHexString(bytesKey));
//			System.out.println("stringKey:"+new String(bytesKey));//打印出来的是乱码
			
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");//算法/工作方式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk king des encrypt :"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk king des decrypt :"+new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
