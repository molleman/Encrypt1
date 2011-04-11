//************************************************************
//************************************************************
//  Encrypt0
//  Copyright (c) 2011 by  Stefano Molle
//  ALL RIGHTS RESERVED
//************************************************************
//************************************************************
// Date: 11/03/2011               Coded by: Stefano Molle (MECT) 10212220
// Module name: CA 644
//                                Source file: Encrypt1.java
// Program description:
// This program fullfills the requirements for Continuous Assessment for
// public key Cryptography and security protocols
//************************************************************

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;


public class Encrypt1 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			String message = "";
			int port = 8003;
			String ip ="127.0.0.1" ;
			//the byte data to be sent across encrypted
			byte[] b = {0x08,0x03,0x00,0x07,0x07,0x07,0x00,0x07,0x07,0x09,0x07,0x08,0x09,0x05};
			
			if(args.length == 1){
				message = args[0];
			}else if (args.length == 2){
				ip = args[0]; 
				message = args[1];
			}else if(args.length == 3){
				ip = args[0];
				port = Integer.parseInt(args[1]);
				message = args[2];
			}else{
				System.out.println("Incorrect arguments given:3");
				System.exit(1);
			}
			Socket socket = new Socket(ip,port);
			DataOutputStream out = new DataOutputStream(socket.getOutputStream());
			DataInputStream in = new DataInputStream(socket.getInputStream());
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			ByteArrayOutputStream encryptBuf = new ByteArrayOutputStream();

			//Encode the binary data and message as a nested encode
			encodeNested(buf, message, b);
			//Encrypt the Message
			byte[] encryptedBinMessage = Helper.encrypt(buf.toByteArray());
			//Encode the encypted message as a binary encode
			Helper.encodeBin(encryptBuf, encryptedBinMessage);
			//Convert buffer to byte array and send to server
			out.write(encryptBuf.toByteArray());
			
			//Start receiving data + decode the binary encode to retrieve encrypted ciphertext
			byte[] response1 = Helper.decodeBin(in);
			//Decypted cipher text
			byte[] decryted = Helper.decrypt(response1);
			
			ByteArrayInputStream bais = new ByteArrayInputStream(decryted);
			//Decode the nested encode to retrieve two byte array's within an ArrayList
			//1st byte array holds the binary data and the 2nd holds the string data
			ArrayList decoded = Helper.decodeFromServer(bais);
			byte[] bytesDecoded = (byte[])decoded.get(0);
			
			for(int i = 0; i < bytesDecoded.length; i++){
				
				if(bytesDecoded[i] != b[i]){
					System.out.println("they are the not same bytes, exiting system");
					System.exit(0);
				}
				
			}
			
			byte[] stringDecoded = (byte[]) decoded.get(1);
			
			//Create the string from the byte array
			String resposeString = new String(stringDecoded);
			
			//print out the data
			System.out.println("");
			System.out.println("Connected to remote address "+ socket.getRemoteSocketAddress().toString().substring(1));
			System.out.println("Connected from the local address " + socket.getLocalSocketAddress().toString().substring(1));
			System.out.println("String received = "+resposeString.substring(0,resposeString.length()-2));
			System.out.println("Binary data Received contained " + bytesDecoded.length+" Bytes");
			System.out.println("");
			
			out.close();
			in.close();
			socket.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
    public static void encodeNested(ByteArrayOutputStream buf,String message, byte[] binData){  	
    	buf.write(0x04);
    	//encode the string with the correct encoding for a nested string
    	Helper.encodeString(buf,message,true);
    	//encode the binary data with the correct encoding for a nested string
    	Helper.encodeBin(buf,binData,true);
    	buf.write(0x00);
    	buf.write(0x00);
    	
    }
    

    	

}
