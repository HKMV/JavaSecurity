package com.king.security.pbe;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class ImoocPBE {

	private static String src = "imooc security pbe";
	
	public static void main(String[] args) {
		jdkPBEWITHMD5andDES();
		jdkPBEWITHSHA1andDES();

	}
	/**
	 * 在设置addProvider之后，如果jdk提供了算法的实现，
	 * 那么程序就会自动优先选择jdk实现方法
	 * 如果没有提供的话就会选择新添加的provider
	 * 在jdk提供实现方法的前提下，想使用BC的实现方法，
	 * 则要在实例化类的时候显式说明，如Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES"，"BC");
	 * 
	 */
	public static void jdkPBEWITHMD5andDES(){
		try {
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);//8位
			
			//口令和秘钥
			String password = "imooc";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);//迭代100次
			Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk PBEWITHMD5andDES encrypt:"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdk PBEWITHMD5andDES decrypt:"+new String(result));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void jdkPBEWITHSHA1andDES(){
		
		Security.addProvider(new BouncyCastleProvider());
		try {
			//初始化盐
			SecureRandom random = new SecureRandom();
			byte[] salt = random.generateSeed(8);//8位
			
			//口令和秘钥
			String password = "imooc";
			PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHSHA1andDES");
			System.out.println(factory.getProvider());
			Key key = factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);//迭代100次
			Cipher cipher = Cipher.getInstance("PBEWITHSHA1andDES");
			System.out.println(cipher.getProvider());
			cipher.init(Cipher.ENCRYPT_MODE, key, pbeParameterSpec);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk PBEWITHSHA1andDES encrypt:"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key, pbeParameterSpec);
			result = cipher.doFinal(result);
			System.out.println("jdk PBEWITHSHA1andDES decrypt:"+new String(result));
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
