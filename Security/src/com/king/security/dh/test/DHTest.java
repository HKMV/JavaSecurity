package com.king.security.dh.test;


public class DHTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String src = "king security dh";
		
		Sender sender = new Sender();
		Receiver receiver = new Receiver();
		
		sender.initPublicKey();
		receiver.initPublicKey(sender.getPublicKey());
		sender.constructPrivateKey(receiver.getPublicKey());
		receiver.constructPrivateKey();
		
		if(sender.getSenderDesSecretKey().equals(receiver.getReceiverDesSecretKey())){
			System.out.println("私钥相同");
		}
		
		byte[] result = sender.encrypt(src);
		receiver.decrypt(result);
		

	}

}
