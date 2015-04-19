/**
 * Classname SignatureGenerator
 * @version 1.0 06 Mar 2012
 * @author Elaine Abalos
 */

package digitalSignature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import base64.Base64;

/**
 * Class SignatureGenerator is responsible for generating a signature 
 * using SHA256 with RSA algorithm 
 */
public final class SignatureGenerator{
	/**
	 * generated signature in byte array
	 */
	private byte[] signSignature;
	/**
	 * private key
	 */
	private byte[] privateKey;
	/**
	 * signature
	 */
	private Signature signature;
	/**
	 * original data
	 */
	private String data;
	/**
	 * fixed algorithm used in generating signature
	 */
	private final String algorithm="SHA256withRSA";
	
	/**
	 * Initializes the data and private key
	 */
	public SignatureGenerator(String data, byte[] privateKey) 
	{	
		this.privateKey = privateKey;
		this.data = data;
	}
	
	/**
	 * generate signature using SHA256 with RSA algorithm
	 * @return signature
	 */
	public final String generateSignature()
	{
		String strSignature="";
		try {				
			signature = Signature.getInstance(algorithm);
			
			//create private key
			final String algo = "RSA";
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey);
			KeyFactory kf = KeyFactory.getInstance(algo);
			PrivateKey pk = kf.generatePrivate(privateKeySpec);	
					
			signature.initSign(pk);								//use private key for initialization
			
			byte[] dataByte = data.getBytes();					//get the bytes of the input data
			signature.update(dataByte);							//supply the data to the signature			
			signSignature = signature.sign();					//sign the signature
			
			//FileOutputStream sigfos = new FileOutputStream("signFile");
			//sigfos.write(sign);
			//sigfos.close();   
			strSignature = Base64.encodeToString(signSignature, true);
			   					    
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Private key algorithm does not exist (generate signature)");
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used in generating signature");
		} catch (SignatureException e) {			
			throw new RuntimeException("Signature exception caught in generating signature");
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Invalid key specifications exception caught in generating signature");
		};
		
		return strSignature;
	}
}
