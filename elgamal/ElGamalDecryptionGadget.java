package projects.elgamal;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import circuit.operations.Gadget;
import examples.gadgets.math.ModGadget;
import examples.gadgets.math.FieldDivisionGadget;

public class ElGamalDecryptionGadget extends Gadget {

	private Wire c1; // g^r
    private Wire c2; // cipher text = y^r * M
    private Wire x; // sk
	private Wire one; // dummy data

	private Wire[] plaintext;

	public ElGamalDecryptionGadget(Wire c1, Wire c2, Wire x, Wire one, String... desc) {
		super(desc);

        this.c1 = c1;
        this.c2 = c2;
        this.x = x;
        this.one = one;

		buildCircuit();
	}

	private void buildCircuit() {
		// 1. c1^x
		Wire tmp_c1 = c1.mul(one);							// 한 사이클마다 c1의 값이 제곱으로 증가됨
		Wire c1_x = one.mul(one);						    // c1^x (결과가 저장될 wire)
		Wire[] xBitArray = x.getBitWires(254).asArray();	// x을 bit array로 변환
		for(int i=0; i<xBitArray.length; i++) { // 0번째 index가 맨 아랫자리 숫자
			// 1. xBitArray[i] == 1
			//		oneBit = 1 * tmp_c1 = tmp_c1
			//		zeroBit = (1-1).checkNonZero() = 0
			//	=> realValue = tmp_c1 + 0 = tmp_c1
			// 2. rBitArray[i] == 0
			//		oneBit = 0 * tmp_c1 = 0
			//		zeroBit = (0-1).checkNonZero() = 1
			// => realValue = 0 + 1 = 1

			Wire oneBit = xBitArray[i].mul(tmp_c1);
			Wire zeroBit = xBitArray[i].sub(new BigInteger("1")).checkNonZero();
			Wire realValue = oneBit.add(zeroBit);

			c1_x = c1_x.mul(realValue);
			tmp_c1 = tmp_c1.mul(tmp_c1);
		}

        // 2. c2 / c1^x (mod p)
        FieldDivisionGadget fieldDivisionGadget = new FieldDivisionGadget(c2, c1_x);
        plaintext = fieldDivisionGadget.getOutputWires();
	}
	
	@Override
	public Wire[] getOutputWires() {
        return plaintext;
	}

}
