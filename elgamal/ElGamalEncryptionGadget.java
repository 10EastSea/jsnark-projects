package projects.elgamal;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import circuit.operations.Gadget;

public class ElGamalEncryptionGadget extends Gadget {

	private Wire M; // plain text
	private Wire g; // generator = 5
	private Wire y; // pk = g^x
	private Wire one; // dummy data

	private Wire r;
	private Wire g_r;
	private Wire ciphertext;

	public ElGamalEncryptionGadget(Wire M, Wire g, Wire y, Wire one, String... desc) {
		super(desc);

		this.M = M;
		this.g = g;
		this.y = y;
		this.one = one;

		buildCircuit();
	}

	private void buildCircuit() {
		r = generator.createConstantWire(Util.nextRandomBigInteger(Config.FIELD_PRIME)); // 랜덤 r 생성 (랜덤 값은 circuit에서 생성하는게 맞으나, 여기선 임시로 gadget에서 생성)
		// r = one.mul(new BigInteger("3")); // test code

		// 1. g^r
		Wire tmp_g = g.mul(one);							// 한 사이클마다 g의 값이 제곱으로 증가됨
		g_r = one.mul(one);									// g^r (결과가 저장될 wire)
		Wire[] rBitArray = r.getBitWires(254).asArray();	// r을 bit array로 변환
		for(int i=0; i<rBitArray.length; i++) { // 0번째 index가 맨 아랫자리 숫자
			// 1. rBitArray[i] == 1
			//		oneBit = 1 * tmp_g = tmp_g
			//		zeroBit = (1-1).checkNonZero() = 0
			//	=> realValue = tmp_g + 0 = tmp_g
			// 2. rBitArray[i] == 0
			//		oneBit = 0 * tmp_g = 0
			//		zeroBit = (0-1).checkNonZero() = 1
			// => realValue = 0 + 1 = 1

			Wire oneBit = rBitArray[i].mul(tmp_g);
			Wire zeroBit = rBitArray[i].sub(new BigInteger("1")).checkNonZero();
			Wire realValue = oneBit.add(zeroBit);

			g_r = g_r.mul(realValue);
			tmp_g = tmp_g.mul(tmp_g);
		}

		// 2. y^r
		Wire tmp_y = y.mul(one);							// 한 사이클마다 y의 값이 제곱으로 증가됨
		Wire y_r = one.mul(one);							// y^r (결과가 저장될 wire)
		for(int i=0; i<rBitArray.length; i++) { // 0번째 index가 맨 아랫자리 숫자
			// 1. rBitArray[i] == 1
			//		oneBit = 1 * tmp_y = tmp_y
			//		zeroBit = (1-1).checkNonZero() = 0
			//	=> realValue = tmp_y + 0 = tmp_y
			// 2. rBitArray[i] == 0
			//		oneBit = 0 * tmp_y = 0
			//		zeroBit = (0-1).checkNonZero() = 1
			// => realValue = 0 + 1 = 1

			Wire oneBit = rBitArray[i].mul(tmp_y);
			Wire zeroBit = rBitArray[i].sub(new BigInteger("1")).checkNonZero();
			Wire realValue = oneBit.add(zeroBit);

			y_r = y_r.mul(realValue);
			tmp_y = tmp_y.mul(tmp_y);
		}

		// 3. y^r * M
		ciphertext = y_r.mul(M);
	}
	
	@Override
	public Wire[] getOutputWires() {
		return new Wire[] { ciphertext };
	}

	public Wire getR() { return r; }
	public Wire getGOfR() { return g_r; }

}
