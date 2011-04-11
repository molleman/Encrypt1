//************************************************************
//************************************************************
//  Encrypt0
//  Copyright (c) 2011 by  Stefano Molle
//  ALL RIGHTS RESERVED
//************************************************************
//************************************************************
// Date: 11/03/2011               Coded by: Stefano Molle (MECT) 10212220
// Module name: CA 644
//                                Source file: Encrypt0.java
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


public class Encrypt0 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			String ip = "127.0.0.1";
			int port = 8002;
			byte[] b = {0x08,0x09,0x07,0x08,0x09,0x05};
			
			String message = "";
			
			
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

			//Encode the data to be sent across
			Helper.encodeString(buf,message);
			Helper.encodeBin(buf, b);

			//Encrypt the data
			byte[] encryptedBinMessage = Helper.encrypt(buf.toByteArray());
			//Then encode it as a binary piece of data
			Helper.encodeBin(encryptBuf, encryptedBinMessage);
			//write it to the server
			out.write(encryptBuf.toByteArray());
			
			//Receive the data
			//remove the binary encoding
			byte[] response1 = Helper.decodeBin(in);
			//Decryption of the data
			byte[] decryted = Helper.decrypt(response1);
			
			ByteArrayInputStream bais = new ByteArrayInputStream(decryted);
			
			// Return the binary and string byte arrays of the actual usuable
			//data
			byte[] binArray = Helper.convertFromServer(bais);
            byte[] stringArray = Helper.convertFromServer(bais);
            
            for(int i = 0; i < binArray.length; i++){
				
				if(binArray[i] != b[i]){
					System.out.println("they are the not same bytes, exiting system");
					System.exit(0);
				}
				
			}
			
            System.out.println("");
            System.out.println("Connected to remote address "+ socket.getRemoteSocketAddress().toString().substring(1));
            System.out.println("Connected from the local address " + socket.getLocalSocketAddress().toString().substring(1));
            System.out.println("String received = " +new String(stringArray));
            System.out.println("Binary data Received contained " +binArray.length+ " Bytes");
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
	
}
