/**
 * Classname AESkeyGenerator
 * @version 1.0 06 Mar 2012
 * @author Elaine Abalos
 * 		   Nikko Bigtas
 * 		   Jameson Ong Lopez
 */

package aes;

import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** 
 * Class AESkeyGenerator is responsible for generating AES 
 * key with a fixed size of 128
 */
public class AESKeyGenerator {			
	/**
	 * AES key
	 */
	private byte[] aesKey;
	/**
	 * Fixed algorithm used for generating AES key
	 */
	private final String algorithm = "AES";
	/**
	 * Fixed size of AES key
	 */
	private static final int AES_KEY_SIZE = 128;
	/**
	 * Key generator
	 */
	private KeyGenerator keyGen;
	/**
	 * Secret key
	 */
	private SecretKey secretKey;
	
	/**
	 * Generates a random AES key
	 */
	public void generateAESKey() {
		try {
		keyGen = KeyGenerator.getInstance(algorithm);

		keyGen.init(AES_KEY_SIZE);
    	secretKey = keyGen.generateKey();
    	aesKey = secretKey.getEncoded();
    	//aesKeySpec = new SecretKeySpec(aesKey, algorithm);

		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Algorithm used in generating AES key does not exist");
		}
	}

	/**
	 * Gets the generated AES key
	 * @return AES key
	 */
	public byte[] getAesKey() {
		return aesKey;
	}
}
