//************************************************************
//************************************************************
//  Encrypt0
//  Copyright (c) 2011 by  Stefano Molle
//  ALL RIGHTS RESERVED
//************************************************************
//************************************************************
// Date: 11/03/2011               Coded by: Stefano Molle (MECT) 10212220
// Module name: CA 644
//                                Source file: Helper.java
// Program description:
// This Class supports in the encoding , decoding encrpytion and decryption
// of data to be sent and received from david gray's server
//************************************************************

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class Helper {
	
	//i have set the max buffer size to 100kb to ensure you cannot keep sending data to overflow my buffer!
	//The program will exit if u go over this limit
	static final int MAX_BUFFER_SIZE = 102400;
/*
 * Encode a string for NT encoding and held in buffer
 */
   public static void encodeString(ByteArrayOutputStream buf,String message){
    	buf.write(0x01);   
        byte[] b = message.getBytes();
        for(int i =1; i<message.getBytes().length+1;i++ ){ 	
        	
        	buf.write(b[i-1]);	
         }
        buf.write(0x00);
        buf.write(0x00);
    }
/*
 * This method will enable me to encode string data as required and append it to a buffer   
 */
	public static void encodeString(ByteArrayOutputStream buf,String message,boolean isNested){
		buf.write(0x01);   
		byte[] b = message.getBytes();
		for(int i =0; i<message.getBytes().length;i++ ){ 	
			buf.write(b[i]);	
        }
		buf.write(0x00);
		buf.write(0x01);
		buf.write(0x00);
		buf.write(0x01);
   }
 /*
  * This method will encode binary data in the correct format and append it to the buffer. This method will handle if the binary
  * data is be included in a nested encoding.   
  */
    public static void encodeBin(ByteArrayOutputStream buf, byte[] binData, boolean isNested){
		buf.write(0x03);
		for(int i=0; i< binData.length ; i++){
			if(binData[i] == 0){
				buf.write(binData[i]);
				buf.write(1);
				buf.write(1);
			}else
				buf.write(binData[i]);
		}		
		buf.write(0x00);
		buf.write(0x01);
		buf.write(0x00);
		buf.write(0x01);
    }

/*
 * This method will encode the supplied binary data as required by the encrypt1 class
 */
   public static void encodeBin(ByteArrayOutputStream buf, byte[] binData){
       	
	buf.write(0x03);
	for(int i=0; i< binData.length ; i++){
		
		if(binData[i] == 0){
			buf.write(binData[i]);
			
			buf.write(1);
		}else{
			buf.write(binData[i]);
		}
	}		
	buf.write(0x00);
	buf.write(0x00);	
   }

/*
 * Removing the binary encoding from the received data. We will check here that
 * a limit of data can only be sent back
 */
    public static byte[] decodeBin(InputStream dis) throws IOException{
    	//Buffer to hold bytes being read in
    	ByteArrayOutputStream buf = new ByteArrayOutputStream();
    	int type = dis.read();
    	if (type == 3){
    		
    		int zeroesInARow = 0;
    		int bytesCounter =0;
    		byte b;
    		
    		
    		
    		while((b = (byte)dis.read()) != -1  ||zeroesInARow < 2) {
    	        
    		if(bytesCounter > MAX_BUFFER_SIZE){
    			System.out.print("Too much data being sent to me, take it easy, lower the data to this many bytes " + MAX_BUFFER_SIZE);
    			System.exit(0);
    		}
    	        if(b == 0x00) {
    	        	zeroesInARow++;
    	        	//remove next byte
    	        	byte c=(byte)dis.read();
    	        	if(c ==0x00){
    	        		zeroesInARow++;
    	        	}else{
    	        		zeroesInARow = 0;
    	        		buf.write(b);
    	        	}
    	        }else{
    	        	zeroesInARow = 0;
    	        	buf.write(b);
    	        }	        
    	        bytesCounter++;
    	    }
    	    return buf.toByteArray();
    	}else{
    		System.out.println("Expected type 1 recevied type +" + type);
    		System.exit(0);
    		return null;
    	}
    	
		
    }

	public static byte[] strip(InputStream dis){
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		int state = 0;
		byte b;
		
		// i use a finite-state recognizer algorithm to handle the decoding of 0 1 and 0 1 0 1
		try {
			while((b=(byte)dis.read()) !=-1){
				switch(state){
	
				case 0:
					if(b == 0x00){
						//System.out.println("whats going on");
						state = 1;
						buf.write(b);
					}else
						output.write(b);
					
					break;
				case 1: // We've seen a 0x00
					if(b == 0x00){
						state = 1;
						buf.write(b);
					}else if(b == 0x01){
						state = 2;
		                buf.write(b);
					}
					else{
						output.write(buf.toByteArray());
						buf.reset();
						state =0;
					}
					break;
				case 2: // We've seen 0x00,0x01
					if(b == 0x00){
						state =3;
						buf.write(b);
					}else if(b==0x01){
						
						output.write(0x00);
						buf.reset();
						state = 0;
						
					}
					else{
						
						output.write(buf.toByteArray());
						buf.reset();
						state=0;
					}
					break;
				case 3: // We've seen 0x00,0x01,0x00
					if(b == 0x00){
						state = 1;
						output.write(buf.toByteArray());
						buf.reset();
						buf.write(b);
					}else if (b == 0x01){
						 // The last four input bytes were 0x00,0x01,0x00,0x01
						state = 0;
						byte[] zeroes = {0x00,0x00};
						output.write(zeroes);
					}else{
						output.write(buf.toByteArray());
						buf.reset();
						state =0;
					}
					break;
				}
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return output.toByteArray();
	}
/*
 *  Convert the data received from the server into the string and binary data  
 */
   public static byte[] convertFromServer(InputStream dis) throws IOException{
    	//Buffer to hold bytes being read in
    	ByteArrayOutputStream buf = new ByteArrayOutputStream();
    	
    	int type = dis.read() ;
    	 
    	if(type ==1) {
    	    int zeroesInARow = 0;

    	    while(zeroesInARow < 2) {
    	        int b = dis.read();
    	        if(b == 0x00){
    	        	zeroesInARow++;
    	        }
    	        else{
    	        	zeroesInARow = 0;
    	        }
    	        buf.write(b);
    	    }

    	    //String messageRecevied = rawMessage.substring(0,rawMessage.length()-2);
    	    return buf.toByteArray();
    	    
    	}else if (type == 3){
    		int zeroesInARow = 0;
    		int bytesCounter =0;
    		
    		
    	    while(zeroesInARow < 2) {
    	        byte b = (byte)dis.read();
    	        
    	        if(b == 0x00) {
    	        	zeroesInARow++;
    	        	//remove next byte
    	        	byte c=(byte)dis.read();
    	        	if(c ==0x00){
    	        		zeroesInARow++;
    	        	}else{
    	        		zeroesInARow = 0;
    	        		buf.write(b);
    	        	}
    	        }else{
    	        	zeroesInARow = 0;
    	        	buf.write(b);
    	        }	        
    	        bytesCounter++;
    	    }
    	   
    	    return buf.toByteArray();
    	    
    	}else{
    		System.out.println("type:" +type + " was not expected");
    		return null;
    	}

    }

	
/*
 * This method will decode a nested encode and recursively decode the each part of the nested encode, place it in
 * an array list and return to the object calling the method.
 *Depending on the type being read in by the input stream , this method will handle the data differently.
 *
 */
	public static ArrayList decodeFromServer(InputStream dis) throws IOException{
    	//Buffer to hold bytes being read in
    	ByteArrayOutputStream buf = new ByteArrayOutputStream();
    	ArrayList byteArrayList = new ArrayList();
   
    	int type = dis.read() ;
    	
    	 
    	if(type ==1) {
    	    int zeroesInARow = 0;

    	    while(zeroesInARow < 2) {
    	        int b = dis.read();
    	        
    	        if(b == 0x00){
    	        	zeroesInARow++;
    	        }
    	        else {
    	        	zeroesInARow = 0;
    	        }
    	        buf.write(b);
    	    }    	    
    	    byteArrayList.add(buf.toByteArray());
    	    buf.reset();
    	    
    	    return byteArrayList;
    	}else if (type == 3){
    		
    		ByteArrayOutputStream output = new ByteArrayOutputStream();
			ByteArrayOutputStream buf1 = new ByteArrayOutputStream();
    		
			int state = 0;
    		int zeroesInARow = 0;
    		
    		byte b ;
    		while((b = (byte)dis.read()) != -1||zeroesInARow < 2) {

				switch(state){
					case 0 :
					 	if(b == 0x00){
							zeroesInARow++;
							buf1.write(b);//the 0x00
							state = 1;
					    }else{
					    	buf1.reset();
							output.write(b);
							state = 0;
					    }
					  break;
					case 1: //we have seen 1 0x00
						if(b == 0x00){ // now we have seen 2
							
							state =0;
							buf1.reset();
							zeroesInARow++;
						}else{ //we see a different number//false alarm
							buf1.write(b);
							
							output.write(buf1.toByteArray());
							buf1.reset();
							state =0;
						}
						break;
				}
				
    	    } 
    		
    		byteArrayList.add(output.toByteArray());
    	    return byteArrayList;
  
    	}else if (type ==4){
    	
    		byte[] stripped = strip(dis);
    		
    		ByteArrayInputStream bais = new ByteArrayInputStream(stripped);
    		ByteArrayOutputStream output = new ByteArrayOutputStream();
    		
    		int state = 0;
    		byte b ;
    		while((b=(byte)bais.read()) != -1 ){
    			
				switch(state){

				 case 0 : 
					if(b == 0x00){
						state = 1;
						buf.write(b);
					}else{
						output.write(b);
					}
					break;
				 case 1 : // we have seen one 0
					 if(b == 0x00){
						 state = 0;
						 byte[] bytes = {0x00,0x00};
						 
						 output.write(bytes);
						 
						 ByteArrayInputStream bais1 = new ByteArrayInputStream(output.toByteArray());

						 ArrayList a = decodeFromServer(bais1);
						 
						 //Setting the byte array of bytes to pos 0 of my ArrayList
						 byteArrayList.add(a.get(0));
						 buf.reset();
						 output.reset();
					 }else{
						 state =0;
						 buf.write(b);
						 output.write(buf.toByteArray()); 
						 buf.reset();
					 }
					break;
				}
			}
    		byteArrayList.add(buf.toByteArray());
    		return   byteArrayList ;
    	}else{
    		System.out.println("type : " +type);
    		return null;
    	}

    }
/*
 * This method will enable the program to convert a hex string to a byte array.
 * This method was retrieved from the internet from this 
 * web site http://bit.ly/bncfKB Dave L. member of stackoverflow website   
 */
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
/*
 * This method enables the program to encrypt a byte array with the specific IV and KEY given
 * to us by Dr. Gray	
 */
	public static byte[] encrypt(byte[] input){
		byte[] encrypted ={};
		byte[] iv = Helper.hexStringToByteArray("4178b6009effc1f4373467232ddd33f6");
		byte[] key = Helper.hexStringToByteArray ("4f01b681721ce4e1c417bc5d8241f235");
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128); // 192 and 256 bits may not be available
			 // Generate the secret key specs.
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
	        SecretKeySpec keySpec = null;
	        keySpec = new SecretKeySpec(key, "AES");
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, keySpec,paramSpec);
	        encrypted = cipher.doFinal(input);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encrypted;
	}
/*
 * 	This method enables the program to decrypt a byte array with the specific IV and KEY given
 *  by Dr. Gray
 */
	public static byte[] decrypt(byte[] input){
		byte[] decrypted ={};
		byte[] iv = Helper.hexStringToByteArray("4178b6009effc1f4373467232ddd33f6");
		byte[] key = Helper.hexStringToByteArray ("4f01b681721ce4e1c417bc5d8241f235");
		try{
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128); // 192 and 256 bits may not be available
			 // Generate the secret key specs.
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);	
	        SecretKeySpec keySpec = null;
	        keySpec = new SecretKeySpec(key, "AES");
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.DECRYPT_MODE, keySpec,paramSpec);
	        decrypted = cipher.doFinal(input);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return decrypted;
	}
}
