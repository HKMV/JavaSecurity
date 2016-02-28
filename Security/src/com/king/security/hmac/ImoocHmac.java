package com.king.security.hmac;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class ImoocHmac {

	private static String src = "imooc security hmac";

	public static void main(String[] args) {
		jdkHmacMD5();
		bcHmacMD5();

	}
	
	public static void jdkHmacMD5(){
		try {
			//初始化keygenerator
			KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
			//产生秘钥
			SecretKey secretKey = keyGenerator.generateKey();
			//获得秘钥
			byte[] key = secretKey.getEncoded();
			
			//还原秘钥
			SecretKey restoreSecretKey = new SecretKeySpec(key, "HmacMD5");
			//实例化MAC
			Mac mac = Mac.getInstance("HmacMD5");
			//初始化MAC
			mac.init(restoreSecretKey);
			//执行摘要
			byte[] hmacMD5Bytes = mac.doFinal(src.getBytes());
			System.out.println("jdk hmacMD5:"+Hex.toHexString(hmacMD5Bytes));
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void bcHmacMD5(){
		//实例化
		HMac hMac = new HMac(new MD5Digest());
		//初始化
		hMac.init(new KeyParameter(Hex.decode("aaaaaaaaaa")));
		hMac.update(src.getBytes(), 0, src.getBytes().length);
		
		byte [] hmacMD5Bytes = new byte[hMac.getMacSize()];
		hMac.doFinal(hmacMD5Bytes, 0);
		
		System.out.println("bc hmacMD5:"+Hex.toHexString(hmacMD5Bytes));
	}

}
