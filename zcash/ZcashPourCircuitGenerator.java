package projects.zcash;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import projects.zcash.ZcashMerkleTreePathGadget;

public class ZcashPourCircuitGenerator extends CircuitGenerator {

	private Wire[] rt, sn_old, cm_new;
	private Wire v_pub;

	private Wire[] path, c_old, addr_old_sk, c_new;
	private Wire directionSelector;

	private int treeHeight;
	private int hashDigestDimension = 8;
	private int coinSize = 28;
	
	public ZcashPourCircuitGenerator(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		
		/** declare inputs **/
		
		rt = createInputWireArray(hashDigestDimension, "Root");
		sn_old = createInputWireArray(hashDigestDimension, "Serial Number");
		cm_new = createInputWireArray(hashDigestDimension, "Commit");
		v_pub = createInputWire("Public Value");

		path = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Path");
		directionSelector = createProverWitnessWire("Direction Selector");
		c_old = createProverWitnessWireArray(coinSize, "Old Coin");
		addr_old_sk = createProverWitnessWireArray(hashDigestDimension * 2, "Secret Key Address");
		c_new = createProverWitnessWireArray(coinSize, "New Coin");

		/** connect gadget **/

		Wire[] cm_old = new Wire[hashDigestDimension];
		for(int i=0; i<hashDigestDimension; i++) { cm_old[i] = c_old[i+20]; }
		ZcashMerkleTreePathGadget merkleTreeGadget = new ZcashMerkleTreePathGadget(directionSelector, cm_old, path, 32, treeHeight); // BigInteger range: 32 bits
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();
		
		/** Now compare the actual root with the public known root **/
		Wire errorAccumulator = getZeroWire();
		for(int i = 0; i < hashDigestDimension; i++){
			Wire diff = actualRoot[i].sub(rt[i]);
			Wire check = diff.checkNonZero();
			errorAccumulator = errorAccumulator.add(check);
		}

		makeOutputArray(actualRoot, "Computed Root");
		
		/** Expected mismatch here if the sample input below is tried**/
		makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {

		///////////////////////////////////////////////////
		// input x = (rt, sn_old, cm_new, v_pub)         //
		//	- PRFaddr, PRFsn, PRFpk => same PRF function //
		//	- PRF, COMM function => SHA256 function      //
		///////////////////////////////////////////////////

		// !! rt (hash value): array size 8 <- big integer 32 bits => 256 bits
		circuitEvaluator.setWireValue(rt[0], new BigInteger("3081078286"));
		circuitEvaluator.setWireValue(rt[1], new BigInteger("1087911990"));
		circuitEvaluator.setWireValue(rt[2], new BigInteger("1987305125"));
		circuitEvaluator.setWireValue(rt[3], new BigInteger("1814218270"));
		circuitEvaluator.setWireValue(rt[4], new BigInteger("3759931758"));
		circuitEvaluator.setWireValue(rt[5], new BigInteger("0257844124"));
		circuitEvaluator.setWireValue(rt[6], new BigInteger("3938464974"));
		circuitEvaluator.setWireValue(rt[7], new BigInteger("3550324813"));

		// sn_old (hash value): PRF(a_old_sk | p_old)
		circuitEvaluator.setWireValue(sn_old[0], new BigInteger("1842397534"));
		circuitEvaluator.setWireValue(sn_old[1], new BigInteger("1438854622"));
		circuitEvaluator.setWireValue(sn_old[2], new BigInteger("1341541397"));
		circuitEvaluator.setWireValue(sn_old[3], new BigInteger("0008680022"));
		circuitEvaluator.setWireValue(sn_old[4], new BigInteger("2922258890"));
		circuitEvaluator.setWireValue(sn_old[5], new BigInteger("0198763429"));
		circuitEvaluator.setWireValue(sn_old[6], new BigInteger("3258633035"));
		circuitEvaluator.setWireValue(sn_old[7], new BigInteger("2225199822"));

		// cm_new (hash value): COMM(s_new | COMM(r_new | a_new_pk | p_new) | v_new)
		circuitEvaluator.setWireValue(cm_new[0], new BigInteger("1426159927"));
		circuitEvaluator.setWireValue(cm_new[1], new BigInteger("1036572336"));
		circuitEvaluator.setWireValue(cm_new[2], new BigInteger("3608559607"));
		circuitEvaluator.setWireValue(cm_new[3], new BigInteger("1604140848"));
		circuitEvaluator.setWireValue(cm_new[4], new BigInteger("0348381931"));
		circuitEvaluator.setWireValue(cm_new[5], new BigInteger("1673394319"));
		circuitEvaluator.setWireValue(cm_new[6], new BigInteger("1976216296"));
		circuitEvaluator.setWireValue(cm_new[7], new BigInteger("0271883356"));

		// v_pub (value): integer 1 => 32 bits
		circuitEvaluator.setWireValue(v_pub, new BigInteger("118112"));


		//////////////////////////////////////////////////////////////////
		// witness x = (path, c_old, addr_old_sk, c_new)                //
		//	- c_old = (addr_old_pk, v_old, p_old, r_old, s_old, cm_old) //
		//	- c_new = (addr_new_pk, v_new, p_new, r_new, s_new, cm_new) //
		//	- addr_old_pk = (a_old_pk, pk_old_enc)                      //
		//	- addr_new_pk = (a_new_pk, pk_new_enc)                      //
		//	- addr_old_sk = (a_old_sk, sk_old_enc)                      //
		//////////////////////////////////////////////////////////////////

		// path (hash value array): array size numOfHashValue*8
		circuitEvaluator.setWireValue(directionSelector, new BigInteger("7")); // 7 -> binary: 111 -> 3 bits
		for(int i=0; i<hashDigestDimension; i++) { circuitEvaluator.setWireValue(path[i], new BigInteger("1234567890")); }
		for(int i=hashDigestDimension; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(path[i], new BigInteger("0987654321")); }
		for(int i=hashDigestDimension*2; i<hashDigestDimension*3; i++) { circuitEvaluator.setWireValue(path[i], new BigInteger("1357924680")); }
		
		// c_old: array size 28 (8*2, 1, 1, 1, 1, 8)
		circuitEvaluator.setWireValue(c_old[0], new BigInteger("0914240372")); // a_old_pk
		circuitEvaluator.setWireValue(c_old[1], new BigInteger("3496280708"));
        circuitEvaluator.setWireValue(c_old[2], new BigInteger("2255551198"));
        circuitEvaluator.setWireValue(c_old[3], new BigInteger("3184610359"));
        circuitEvaluator.setWireValue(c_old[4], new BigInteger("3733949825"));
        circuitEvaluator.setWireValue(c_old[5], new BigInteger("2789508313"));
        circuitEvaluator.setWireValue(c_old[6], new BigInteger("1416263883"));
        circuitEvaluator.setWireValue(c_old[7], new BigInteger("2913123281"));
		for(int i=8; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(c_old[i], new BigInteger("112111101")); } // pk_old_enc
        circuitEvaluator.setWireValue(c_old[16], new BigInteger("118")); // v
        circuitEvaluator.setWireValue(c_old[17], new BigInteger("112")); // p
        circuitEvaluator.setWireValue(c_old[18], new BigInteger("114")); // r
        circuitEvaluator.setWireValue(c_old[19], new BigInteger("115")); // s
		circuitEvaluator.setWireValue(c_old[20], new BigInteger("0643332122")); // cm_old
		circuitEvaluator.setWireValue(c_old[21], new BigInteger("1788938999"));
		circuitEvaluator.setWireValue(c_old[22], new BigInteger("3968257017"));
		circuitEvaluator.setWireValue(c_old[23], new BigInteger("0430293487"));
		circuitEvaluator.setWireValue(c_old[24], new BigInteger("3784306191"));
		circuitEvaluator.setWireValue(c_old[25], new BigInteger("0785929505"));
		circuitEvaluator.setWireValue(c_old[26], new BigInteger("0011907385"));
		circuitEvaluator.setWireValue(c_old[27], new BigInteger("2945716847"));

		// addr_old_sk: array size 16 (8, 8)
		for(int i=0; i<hashDigestDimension; i++) { circuitEvaluator.setWireValue(addr_old_sk[i], new BigInteger("97111112")); } // a_old_sk
		for(int i=8; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(addr_old_sk[i], new BigInteger("115111101")); } // sk_old_enc

		// c_new: array size 28 (8*2, 1, 1, 1, 1, 8)
		circuitEvaluator.setWireValue(c_new[0], new BigInteger("0358622199")); // a_new_pk
		circuitEvaluator.setWireValue(c_new[1], new BigInteger("2784671395"));
        circuitEvaluator.setWireValue(c_new[2], new BigInteger("1864958879"));
        circuitEvaluator.setWireValue(c_new[3], new BigInteger("00590219167"));
        circuitEvaluator.setWireValue(c_new[4], new BigInteger("4024366671"));
        circuitEvaluator.setWireValue(c_new[5], new BigInteger("1109992544"));
        circuitEvaluator.setWireValue(c_new[6], new BigInteger("2890652161"));
        circuitEvaluator.setWireValue(c_new[7], new BigInteger("3326960328"));
		for(int i=8; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(c_new[i], new BigInteger("112110101")); } // pk_new_enc
        circuitEvaluator.setWireValue(c_new[16], new BigInteger("118")); // v
        circuitEvaluator.setWireValue(c_new[17], new BigInteger("112")); // p
        circuitEvaluator.setWireValue(c_new[18], new BigInteger("114")); // r
        circuitEvaluator.setWireValue(c_new[19], new BigInteger("115")); // s
		circuitEvaluator.setWireValue(c_new[20], new BigInteger("1426159927")); // cm_new
		circuitEvaluator.setWireValue(c_new[21], new BigInteger("1036572336"));
		circuitEvaluator.setWireValue(c_new[22], new BigInteger("3608559607"));
		circuitEvaluator.setWireValue(c_new[23], new BigInteger("1604140848"));
		circuitEvaluator.setWireValue(c_new[24], new BigInteger("0348381931"));
		circuitEvaluator.setWireValue(c_new[25], new BigInteger("1673394319"));
		circuitEvaluator.setWireValue(c_new[26], new BigInteger("1976216296"));
		circuitEvaluator.setWireValue(c_new[27], new BigInteger("0271883356"));
	}
	
	public static void main(String[] args) throws Exception {
		ZcashPourCircuitGenerator generator = new ZcashPourCircuitGenerator("tree_3_zcash", 3);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}
}
