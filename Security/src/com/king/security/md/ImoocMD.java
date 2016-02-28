package com.king.security.md;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ImoocMD {
	
	private static String src = "imooc security md";

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		jdkMD5();
		jdkMD2();
		bcMD4();
		bcMD5();
		ccMD2();
		ccMD5();
	}
	
	public static void jdkMD5(){
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5Bytes = md.digest(src.getBytes());
			System.out.println("jdkMD5:" + Hex.encodeHexString(md5Bytes));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
	public static void jdkMD2(){
		try {
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md2Bytes = md.digest(src.getBytes());
			System.out.println("jdkMD2:" + Hex.encodeHexString(md2Bytes));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * JDk没有提供MD4算法
	 * 下面通过Security.addProvider()添加算法提供者，实现MD4算法
	 * bc中MD4 和 MD5实现相似
	 */
	public static void bcMD4(){
		
//		Digest digest = new MD4Digest();
//		digest.update(src.getBytes(), 0, src.getBytes().length);
//		byte[] md4Bytes = new byte[digest.getDigestSize()];
//		digest.doFinal(md4Bytes, 0);
//		System.out.println("bcMD4:"+Hex.encodeHexString(md4Bytes));
		
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("MD4");
			//返回提供者
			//md.getProvider()
			byte[] md4Bytes = md.digest(src.getBytes());
			System.out.println("bcMD4:" + Hex.encodeHexString(md4Bytes));
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void bcMD5(){
		//Digest是一个接口，有很多相应的实现类
		Digest digest = new MD5Digest();
		//第一个参数是要摘要的byte，第二个是开始位置，第三个是长度
		digest.update(src.getBytes(), 0, src.getBytes().length);
		byte[] md5Bytes = new byte[digest.getDigestSize()];
		//第一个参数是摘要产生的bytes，第二个是开始位置
		digest.doFinal(md5Bytes, 0);
		System.out.println("bcMD5:"+Hex.encodeHexString(md5Bytes));
	}
	
	
	/**
	 * cc实现的算法就是在jdk的基础上进行一层封装
	 * 就是对jdk的调用，
	 * 所以cc也没有实现md4 算法
	 */
	public static void ccMD5(){
		String md5String = DigestUtils.md5Hex(src.getBytes());
		System.out.println("ccMD5:" + md5String);
	}
	
	public static void ccMD2(){
		String md2String = DigestUtils.md2Hex(src.getBytes());
		System.out.println("ccMD2:" + md2String);
	}

}
