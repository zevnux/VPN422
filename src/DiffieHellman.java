import java.math.BigInteger;
import java.util.Random;

public class DiffieHellman {

	public static BigInteger generateRandomSecretValue() {
		return generate1024BitNum();
	}
	
	public static BigInteger generateBigIntPrime() {
		return new BigInteger(1024, Integer.MAX_VALUE, new Random());
	}
	
	public static BigInteger generateBigIntG() {
		return generate1024BitNum();
	}

	public static BigInteger dhMod(BigInteger g, BigInteger n, BigInteger p) {
		return g.modPow(n, p);
	}
	
	private static BigInteger generate1024BitNum() {
		return new BigInteger(1024, new Random());
	}
}