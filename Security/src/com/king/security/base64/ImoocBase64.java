package com.king.security.base64;

import org.apache.commons.codec.binary.Base64;

/**
 * base64 加密算法
 * @author king
 *
 */
public class ImoocBase64 {

	private static String src = "imooc security base64";
	
	public static void main(String[] args) {

		CCBase64();
		BCBase64();
	}

	
	/**
	 * 使用cc包
	 */
	public static void CCBase64(){
		byte[] encodeBytes = Base64.encodeBase64(src.getBytes());
		System.out.println("CC encode:" + new String(encodeBytes));
		
		byte[] decodeBytes = Base64.decodeBase64(encodeBytes);
		System.out.println("CC decode:" + new String(decodeBytes));
	}
	
	/**
	 * 使用bc包
	 */
	public static void BCBase64(){
		byte[] encodeBytes = org.bouncycastle.util.encoders.Base64.encode(src.getBytes());
		System.out.println("BC encode:" + new String(encodeBytes));
		
		byte[] decodeBytes = org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
		System.out.println("BC decode:" + new String(decodeBytes));
		
	}
}
