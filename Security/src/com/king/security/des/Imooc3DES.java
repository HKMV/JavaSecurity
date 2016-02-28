package com.king.security.des;

import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class Imooc3DES {
	
	private static String src = "imooc security 3des";

	
	public static void main(String[] args) {
		long start = System.currentTimeMillis();
		jdk3DES();
		long end = System.currentTimeMillis();
		System.out.println("jdk time:"+(end - start));
		bc3DES();
		start = System.currentTimeMillis();
		System.out.println("bc time:"+(start - end));

		//通过比较可以知道jdk运算比bc快2倍左右
	}
	
	
	public static void jdk3DES(){
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//			keyGenerator.init(168);//初始化，秘钥长度为168.或者用下面的方式进行初始化
			//SecureRandom的作用是生成默认长度的key
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			System.out.println("bytesKey:"+Hex.toHexString(bytesKey));
//			System.out.println("stringKey:"+new String(bytesKey));//打印出来的是乱码
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");//算法/工作方式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt :"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decrypt :"+new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void bc3DES(){
		
		Security.addProvider(new BouncyCastleProvider());
		
		try {
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
//			keyGenerator.init(168);//初始化，秘钥长度为168
			//SecureRandom的作用是生成默认长度的key
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			System.out.println("bytesKey:"+Hex.toHexString(bytesKey));
//			System.out.println("stringKey:"+new String(bytesKey));//打印出来的是乱码
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding","BC");//算法/工作方式/填充方式
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc 3des encrypt :"+Hex.toHexString(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			result = cipher.doFinal(result);
			System.out.println("bc 3des decrypt :"+new String(result));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	

}
