import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Implement your attack in this class

public class Attack2 {

	private static Cipher dcipher;
	private static SecretKeySpec sharedKey;
	private static Cipher sessionCipher;
	private static String finalData;

	public static void main(String[] args) {

		try {
			
			//For decrypting the cipher is initialised
			dcipher = Cipher.getInstance("DES/ECB/NoPadding");

			//Alice is initialised
			Alice a = new Alice();
			//Bob is initialised
			Bob b = new Bob();

			//Alice sends 64 bit encrypted random value  to Bob which is taken by the intruder
			byte[] random64B = a.Step1();
			//Bob send back session key encoded data back to Alice, which is also taken by the intruder
			byte[] bobData = b.Step2(random64B);			
			//Takes the final encrypted data from Alice to Bob which is encrypted with the session key
			String aliceData = a.Step3(bobData);
			
			//Brute force bob's encoded data to get public key.
			String publicKey=getKeyByBruteForce(random64B, bobData, aliceData);
			/*if(publicKey!=null){
				//Once public key is received, we can use it to decrypt all bobs messages from now onwards to get session key
				sharedKey = new SecretKeySpec(publicKey.getBytes(), "DES");
				dcipher.init(Cipher.DECRYPT_MODE, sharedKey);
				//decrypting the received package
				byte[] decryptedPackage = dcipher.doFinal(bobData);
				
								
				//Takes the final encrypted data from Alice to Bob which is encrypted with the session key
				String aliceData = a.Step3(bobData);
				
				

			}else{
				System.out.println("Key Not Found!");
			}*/
			

		} catch (InvalidKeyException | NoSuchAlgorithmException
				| NoSuchPaddingException | IllegalStateException
				| IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static String getKeyByBruteForce(byte[] random64b, byte[] bobData, String aliceData) {

		//The characters which are used to try as 8 byte password
		//The passCharacters can be altered with more characters to check
		String passCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		//Initializing the index of each place holder of the password to 0
		int[] passwordIndex = { 0, 0, 0, 0, 0, 0, 0, 0 };
		//Initializing the tempPass to initial or first password in the sequence 'AAAAAAAA'
		String tempPass = "AAAAAAAA";
		SecretKeySpec tempKey;
		byte[] outputData;
		byte[] decryptedRandom64b;
		
		//Iterate through all the key combinations until the last placeholder has gone through all characters
		while (passwordIndex[7] <= 25) {
			
			//System.out.println("Password tried "+tempPass);
			
			try {
				//Creating key based on the current 8 byte character
				tempKey = new SecretKeySpec(tempPass.getBytes(), "DES");

				//Initiaize the Cipher with the current key
				dcipher.init(Cipher.DECRYPT_MODE, tempKey);
				//collect the output of decrypted data
				outputData = dcipher.doFinal(bobData);
				//Decrypting the random value send by Alice
				decryptedRandom64b = dcipher.doFinal(random64b);
				
				//Collect the random value which is added in the first block 
				byte[] randomValue = new byte[(outputData.length) / 2];
				System.arraycopy(outputData, 0, randomValue, 0,
						randomValue.length);

				//Check if the random value send by Alice is returned with the Bob's encrypted session key, if yes, key has been found
				if (Arrays.equals(decryptedRandom64b, randomValue)) {
					//Taking the session key part from the data
					byte[] XORedSessionKey = new byte[outputData.length/2];
					System.arraycopy(outputData, outputData.length/2, XORedSessionKey, 0, XORedSessionKey.length);

					//calculating random + 1
					byte[] randomPlusOne = CommonFunctions.incrementByValue(decryptedRandom64b, (byte)1);

					//extracting the session key
					byte[] s = CommonFunctions.XOR(XORedSessionKey, randomPlusOne);

					//regenerating the session key
					SecretKey sessionKey = new SecretKeySpec(s, 0, s.length, "DES");
					sessionCipher = Cipher.getInstance("DES");
					//encrypting the important message
					sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);

					//Since we already have the session key, use it to decrypt the data.
					finalData=CommonFunctions.decrypt(sessionCipher, aliceData);
					
					if(finalData.startsWith("[SECRET]")){
						System.out.println("Final Data is "+finalData);
					
						System.out.println("The Key is Found! and is " + tempPass);
						return tempPass;
					}
				}

			} catch (InvalidKeyException | IllegalStateException
					| IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException e) {

			}

			// Trying next password

			//Iterating through each password combinations and assign it to the tempPass
			String lastPass=tempPass;
			tempPass="";
			for (int i = 0; i <= 7; ++i) {

				++passwordIndex[i];
				if (passwordIndex[i] > passCharacters.length()-1) {
					passwordIndex[i] = 0;
					tempPass=tempPass+passCharacters.charAt(passwordIndex[i]);
				} else {
					tempPass=tempPass+passCharacters.charAt(passwordIndex[i]);
					tempPass+=lastPass.substring(i+1);
					break;
				}

			}
		}

		return null;
	}
}

