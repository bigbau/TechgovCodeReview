/**
 * Classname Encryptor
 * @version 1.0 06 Mar 2012
 * @author Elaine Abalos
 */
package aes;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import base64.Base64;

/**
 * Class Encryption is responsible for encrypting AES key and the 
 * input string using RSA public and private key.
 */
public final class Encryptor {
	
	/**
	 * AES key
	 */
	private byte[] aesKey;
	/**
	 * encrypted AES key
	 */
	private String newKey;
	/**
	 * fixed key pair algorithm
	 */
	private final String keyPairAlgo = "RSA";
	/**
	 * fized AES key algorithm
	 */
	private final String aesAlgo = "AES";
	/**
	 * public key cipher
	 */
	private Cipher pkCipher;
	/**
	 * AES key cipher
	 */
	private Cipher aesCipher;
	/**
	 * Secret key spec
	 */
	private SecretKeySpec aesKeySpec;

	/**
	 * Creates RSA public key cipher and AES shared key cipher
	 * @param aesKey - AES key
	 */
	public Encryptor(byte[] aesKey) throws GeneralSecurityException {
		this.aesKey = aesKey;
		pkCipher = Cipher.getInstance(keyPairAlgo);	     				
	    aesCipher = Cipher.getInstance(aesAlgo);						
    	aesKeySpec = new SecretKeySpec(aesKey, aesAlgo);
	}	

	/**
	 * Encrypts the AES key using an RSA public key
	 * @return encrypted AES key 
	 */
	public final String encryptAESKey(byte[] publicKey) {	
		try {
		//creates public key
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(keyPairAlgo);		
		PublicKey pk = keyFactory.generatePublic(publicKeySpec);
		
		//encrypts AES key using the public key
		pkCipher.init(Cipher.ENCRYPT_MODE, pk);							
		byte[] cipherKey = pkCipher.doFinal(aesKey);
		newKey = Base64.encodeToString(cipherKey, true);
		  
		//CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), pkCipher);
		//os.write(aesKey);
		//os.close();	
		//==System.out.println("newKey     (savekey): "+newKey);
		//aesKeySpec = new SecretKeySpec(cipherKey, "AES");
		//System.out.println("aesKeySpec (encrypt): "+aesKeySpec);
		//return newKey;
		
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Public key algorithm does not exist (encrypt AES key)");
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Invalid key specifications in encrypting AES key: ");
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used in encrypting AES key: ");
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Illegal block in encrypting AES key: ");
		} catch (BadPaddingException e) {
			throw new RuntimeException("Bad padding in encrypting AES key: ");
		}
		
		return newKey;		
	}

	/**
	 * Encrypts the data using the AES key
	 */
	public final String encryptText(String data){			
		String encryptedString="";

		try {
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);
		System.out.println("aesKeySpec (encrypt): "+aesKeySpec);
		
		byte[] cipherText = aesCipher.doFinal(data.getBytes());
		encryptedString =  Base64.encodeToString(cipherText, true);
		
		//System.out.println("new string (encrypt): "+encryptedString);		
		/*FileInputStream is = new FileInputStream(in);
		CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), aesCipher);
		
		System.out.println("size of the input file is: "+in.length());		
		super.copy(is, os);			
		os.close();*/
		
	   } catch (InvalidKeyException e) {
		   throw new RuntimeException("Invalid key used in encrypting input data");	 
	   } catch (IllegalBlockSizeException e) {
		   throw new RuntimeException("Illegal block size exception caught in encrypting input data");
 	   } catch (BadPaddingException e) {
 		  throw new RuntimeException("Caught Bad padding exception caught in encrypting input data");
	   }
		return encryptedString;		
	}
	
}

