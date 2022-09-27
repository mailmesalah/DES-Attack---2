import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Bob {

	private SecretKey sharedKey;
	private static Cipher ecipher;
	private static Cipher dcipher;
	private SecretKey sessionKey;
	private Cipher sessionCipher;

	public Bob() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {

		// Secret key shared by Alice and Bob. 
		// This is just a sample key. Its exact value will be changed during the assessment of the project.
		// So DO NOT assume this will the actual key used in the assessment. 
		sharedKey = new SecretKeySpec("ABCDEFGH".getBytes(), "DES");

		ecipher = Cipher.getInstance("DES/ECB/NoPadding");
		dcipher = Cipher.getInstance("DES/ECB/NoPadding");

		// initialize the ciphers with the given key
		// these are the objects that stores the shared key in them to be used for later encryptions
		ecipher.init(Cipher.ENCRYPT_MODE, sharedKey);
		dcipher.init(Cipher.DECRYPT_MODE, sharedKey);

		// session key will be used for session cipher for encryptions of the secret message
		sessionCipher = Cipher.getInstance("DES");
	}

	public byte[] Step2(byte[] step1package) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {
		if(step1package.length != 8)
		{
			System.out.println("Wrong input pakage size");
			return null;
		}else
		{	
			byte[] decryptedPackage = dcipher.doFinal(step1package);
			
			//calculating random + 1
			byte[] randomPlusOne = CommonFunctions.incrementByValue(decryptedPackage, (byte)1);

			//generating the new session key
			sessionKey = KeyGenerator.getInstance("DES").generateKey();

			//XOR r+1 with the new session key s
			byte[] xoredValue = CommonFunctions.XOR(randomPlusOne, sessionKey.getEncoded());
			
			//concatenating them together
			byte[] step2package = new byte[decryptedPackage.length + xoredValue.length];
			System.arraycopy(decryptedPackage, 0, step2package, 0, decryptedPackage.length);
			System.arraycopy(xoredValue, 0, step2package, decryptedPackage.length, xoredValue.length);
			
			//returning the encrypted package to be sent
			return ecipher.doFinal(step2package);
			
		}
	}
}
