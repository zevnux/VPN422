import java.math.BigInteger;
import java.util.Random;

public class DiffieHellman {

	public static BigInteger generateRandomSecretValue() {
		return generate1024BitNum();
	}
	
	public static BigInteger generateBigIntPrime() {
		return new BigInteger(1024, Integer.MAX_VALUE, new Random()).abs();
	}
	
	public static BigInteger generateBigIntG() {
		return generate1024BitNum();
	}

	public static BigInteger dhMod(BigInteger g, BigInteger n, BigInteger p) {
		return g.modPow(n, p);
	}
	
	public static BigInteger genDHSessionKey(BigInteger g, BigInteger n, BigInteger p) {
		return g.modPow(n, p);
	}
	
	private static BigInteger generate1024BitNum() {
		return new BigInteger(1024, new Random()).abs();
	}
	
	public BigInteger pow(BigInteger base, BigInteger exponent) {
		BigInteger result = BigInteger.ONE;
		while (exponent.signum() > 0) {
			if (exponent.testBit(0)) result = result.multiply(base);
			base = base.multiply(base);
			exponent = exponent.shiftRight(1);
		}
		return result;
	}
}