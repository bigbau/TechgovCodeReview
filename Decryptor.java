/**
 * Classname Decryptor
 * 
 * @version 1.0 06 Mar 2012
 * @author Elaine Abalos
 */
package aes;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import base64.Base64;

/**
 * Class Decryptor is responsible for decrypting the encrypted AES key  
 * using RSA private key and encrypted string using AES key.
 */
public final class Decryptor {
	/**
	 * AES key
	 */
	private byte[] aesKey;
	/**
	 * Fixed private key algorithm
	 */
	private final String privKeyAlgo = "RSA";
	/**
	 * Fixed AES algorithm
	 */
	private final String aesAlgo = "AES";
	/**
	 * public key cipher
	 */
	private Cipher pkCipher;
	/**
	 * aes key cipher
	 */
	private Cipher aesCipher;
	
	/**
	 * Creates RSA private key cipher and AES shared key cipher
	 */
	public Decryptor() throws GeneralSecurityException {			
			pkCipher = Cipher.getInstance(privKeyAlgo);	     
		    aesCipher = Cipher.getInstance(aesAlgo);	
	}
	
	/**
	 * Decrypts AES key using RSA private key
	 * @param encryptedKey  - encrypted AES key
	 * @param privateKey    - private key
	 * @return aesKey       - decrypted AES key 
	 */
	public final byte[] decryptAESKey(String encryptedKey, byte[] privateKey) {		
		
		try {
		byte[] initialDecrypt;
		final int AES_Key_Size = 128;		
		
		//creates private key
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey);		
		KeyFactory kf = KeyFactory.getInstance(privKeyAlgo);
		PrivateKey pk = kf.generatePrivate(privateKeySpec);	
				
		//decrypts AES key using the private key
		pkCipher.init(Cipher.DECRYPT_MODE, pk);
		aesKey = new byte[AES_Key_Size/8];
		initialDecrypt = Base64.decode(encryptedKey);
		aesKey = pkCipher.doFinal(initialDecrypt);

		//CipherInputStream is = new CipherInputStream(new FileInputStream(in), pkCipher);
		//is.read(aesKey);			
		//System.out.println("aesKeySpec (loadkey): "+aesKeySpec);
		
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Public key algorithm does not exist (decrypt AES key)");
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Invalid key specifications exception cuaght in decrypting AES key: ");
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used in decrypting AES key: ");
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Illegal block size exception caught in decrypting AES key: ");
		} catch (BadPaddingException e) {
			throw new RuntimeException("Bad padding exception caught in decrypting AES key ");
		} catch(IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid AES key");
		}
		
		return aesKey;
	}
	
	/**
	 * Decrypts the data using the decrypted AES key
	 * @param data   - input string
	 * @param aesKey - AES key
	 * @return decryptedString - decrypted string 
	 */
	public final String decryptText(String data, byte[] aesKey) {
		String decryptedString="";
		
		try {
			SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");		
			System.out.println("aesKeySpec (decrypt): "+aesKeySpec);

			aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);	
        
			//decrypts encrypted string and converts to a new string
			byte[] initialDecrypt = Base64.decode(data);
			byte[] decryptedData = aesCipher.doFinal(initialDecrypt);
			decryptedString = new String(decryptedData);
			
			//System.out.println("new string (dencrypt): "+decryptedString);
			
			//decrypt the file input
			/*CipherInputStream is = new CipherInputStream(new FileInputStream(in), aesCipher);
			FileOutputStream os = new FileOutputStream(out);	
			super.copy(is, os);
			is.close();
			os.close();
			//in.delete();
			*/

		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used in decrypting input data");
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException("Illegal block size exception caught in decrypting input data");
		} catch (BadPaddingException e) {
			throw new RuntimeException("Bad padding exception cuaght in decrypting input data");
		} catch(IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid input string");
		}
		
		return decryptedString;
	}
	
}
