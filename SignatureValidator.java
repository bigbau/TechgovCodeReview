/**
 * Classname SignatureValidator
 * @version 1.0 06 Mar 2012
 * @author Elaine Abalos
 */
package digitalSignature;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import base64.Base64;

/**
 * Class SignatureValidator is responsible for checking whether the data has been tampered 
 * during the transmission. It generates a new signature based on the decrypted data
 * and will be compared with the old signature
 */
public final class SignatureValidator{
	/**
	 * public key
	 */
	private byte[] publicKey;
	/**
	 * original signature
	 */
	private String signature;
	/**
	 * input string
	 */
	private String data;
	/**
	 * fixed algorithm used in generating signature
	 */
	private final String algorithm="SHA256withRSA";
	
	/**
	 * Initializes the data, old signature and public key of the sender
	 */
	public SignatureValidator(String data, String signature, byte[] publicKey) {
		this.publicKey = publicKey;
		this.signature = signature;
		this.data = data;
	}
	
	/**
	 * Verify whether the new signature matches the old signature
	 * @return true or false
	 */
	public final boolean verify(){	
		boolean verify = false;	
		byte[] strSignature;
		final String algo ="RSA";
		Signature newSign;
		try {
			//decrypt the public key
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey);
			KeyFactory keyFactory = KeyFactory.getInstance(algo);
			PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
			
			//create a Signature object and initialize it with the public key
			newSign = Signature.getInstance(algorithm);
			newSign.initVerify(pubKey);

			//generates new hash value based on the input data
			byte[] dataByte = data.getBytes();
			newSign.update(dataByte);
			strSignature = Base64.decode(signature);
			verify = newSign.verify(strSignature);
			
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("Public key algorithm does not exist (verify signature)");
		} catch (InvalidKeyException e) {
			throw new RuntimeException("Invalid key used in verifying signature");
		} catch (SignatureException e) {
			throw new RuntimeException("Signature exception caught in verifying signature");
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("Invalid key specfications exception caught in verifying signature");
		} catch(NullPointerException e) {
			throw new IllegalArgumentException("Invalid signature");
		}
		return verify;
	}
}
