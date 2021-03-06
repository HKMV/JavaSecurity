package com.king.security.sha;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ImoocSHA {
	
	private static String src = "imooc security sha";
	
	public static void main(String[] args) {
		jdkSHA1();
		bcSHA1();
		bcSHA224_1();
		bcSHA224_2();
		ccSHA1();
		
	}
	
	public static void jdkSHA1(){
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA");
			digest.update(src.getBytes());
			System.out.println("jdk sha1:" + Hex.encodeHexString(digest.digest()));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
	public static void bcSHA1(){
		Digest digest = new SHA1Digest();
		digest.update(src.getBytes(),0,src.getBytes().length);
		byte[] sha1Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(sha1Bytes, 0);
		System.out.println("bc sha1:" + Hex.encodeHexString(sha1Bytes));
		
	}
	
	public static void bcSHA224_1(){
		Digest digest = new SHA224Digest();
		digest.update(src.getBytes(),0,src.getBytes().length);
		byte[] sha224Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(sha224Bytes, 0);
		System.out.println("bc sha224-1:" + Hex.encodeHexString(sha224Bytes));
		
	}
	
	public static void bcSHA224_2(){
		Security.addProvider(new BouncyCastleProvider());
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA224");
			System.out.println("provider:"+digest.getProvider());
			digest.update(src.getBytes());
			System.out.println("bc sha224-2:" + Hex.encodeHexString(digest.digest()));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void ccSHA1(){
		System.out.println("cc sha1-1:" + DigestUtils.sha1Hex(src.getBytes()));
		System.out.println("cc sha1-2:" + DigestUtils.sha1Hex(src));
		
	}

}
