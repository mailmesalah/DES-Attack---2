import java.io.UnsupportedEncodingException;
import java.math.BigInteger; // BigInteger is employed. For reference: http://docs.oracle.com/javase/7/docs/api/java/math/BigInteger.html

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import com.sun.mail.util.BASE64DecoderStream;
import com.sun.mail.util.BASE64EncoderStream;



public class CommonFunctions {

	// concatenate two byte arrays
	public static byte[] concat(byte[] ar1, byte[] ar2)
	{
		if(ar1 == null) return ar2;
		if(ar2 == null) return ar1;
		
		byte[] result = new byte[ar1.length + ar2.length];
		
		System.arraycopy(ar1, 0, result, 0, ar1.length);
		System.arraycopy(ar2, 0, result, ar1.length, ar2.length);

		return result;
	}
	
	// increment the unsigned number reprensented by input array by val
	public static byte[] incrementByValue(byte[]input, byte val)
	{
		if(input == null) return input;

		// add a byte to beginning of input to prevent BigInteger treating it as negative number. 
		// make sure unsign is non-zero so that the conversion back from BigInteger does not shrink
		// the array size.

		byte[] unsign = {0x01};
		byte[] paddedval = {0x00,val};
		byte[] paddedinput = concat(unsign, input);
		
		BigInteger inval = new BigInteger(paddedinput), 
				addval = new BigInteger(paddedval), 
				outval = inval.add(addval);
		byte[] retval = new byte[input.length]; 
				
		System.arraycopy(outval.toByteArray(), 1, retval, 0, input.length);
		
		return retval;
	}

	//XOR for byte arrays
	public static byte[] XOR(byte[] first, byte[] second)
	{	
		if(first.length != second.length) return null;

		byte[] retval = new byte[first.length];

		for(int i=0; i < first.length; ++i)
		{
			// bitwise operations only available for int, so need to type cast back and forth from byte
			retval[i] = (byte)((first[i]^second[i])&0xff);
		}
		
		return retval;

	}

	public static String encrypt(Cipher ecipher,String str) throws UnsupportedEncodingException, IllegalStateException, IllegalBlockSizeException, BadPaddingException 
	{
		String copy = new String(str);
		
		// storing the result into a new byte array. 
		byte[] utf8 = copy.getBytes("UTF8");
		byte[] enc = ecipher.doFinal(utf8);

		// encode to base64
		enc = BASE64EncoderStream.encode(enc);

		return new String(enc);
	}

	public static String decrypt(Cipher dcipher,String str) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException 
	{
		String copy = new String(str);
		
		// decode with base64 to get bytes
		byte[] dec = BASE64DecoderStream.decode(copy.getBytes());
		byte[] utf8 = dcipher.doFinal(dec);

		// create new string based on the specified charset
		return new String(utf8, "UTF8");
	}
	
	// swap the content of the first and the last bytes.
	// return the swapped array without changing the original byte array.
	public static byte[] swap(byte[] b)
	{
		byte[] res = new byte[b.length];
		System.arraycopy(b, 0, res, 0, b.length);
		
		if(b.length < 2) return res;
		
		byte temp = res[0];
		res[0] = res[res.length-1];
		res[res.length-1] = temp;
		return res;
	}
	
	public static void printArray(byte[] a)
	{
		for(int i=0; i < a.length; ++i)
			System.out.print((int)(a[i] & 0xff) + " : ");		
		System.out.println("");
		
	}

}
