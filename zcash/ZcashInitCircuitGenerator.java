package projects.zcash;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import examples.gadgets.hash.SHA256Gadget;

public class ZcashInitCircuitGenerator extends CircuitGenerator {

    private Wire v, p, r, s;
    private Wire[] a_old_sk, a_new_sk;

	private Wire[] a_old_pk, a_new_pk;
    private Wire[] sn_old;
    private Wire[] cm_old, cm_new;

    SHA256Gadget sha2Gadget;
    private int hashDigestDimension = 8;

    public ZcashInitCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
        // inital input
		v = createInputWire();
        p = createInputWire();
        r = createInputWire();
        s = createInputWire();
        a_old_sk = createInputWireArray(hashDigestDimension);
        a_new_sk = createInputWireArray(hashDigestDimension);


        // a_old_pk
		sha2Gadget = new SHA256Gadget(a_old_sk, 32, 32, false, true);
		a_old_pk = sha2Gadget.getOutputWires();
		makeOutputArray(a_old_pk, "a_old_pk");

        // a_new_pk
		sha2Gadget = new SHA256Gadget(a_new_sk, 32, 32, false, true);
		a_new_pk = sha2Gadget.getOutputWires();
		makeOutputArray(a_new_pk, "a_new_pk");


        // sn_old: PRF(a_old_sk | p_old)
        Wire[] tmp_sn_old = new Wire[hashDigestDimension + 1];
        for(int i=0; i<hashDigestDimension; i++) { tmp_sn_old[i] = a_old_sk[i]; }
        tmp_sn_old[hashDigestDimension] = p;

        sha2Gadget = new SHA256Gadget(tmp_sn_old, 32, 36, false, true); // 32 bytes + 4 bytes
		sn_old = sha2Gadget.getOutputWires();
		makeOutputArray(sn_old, "sn_old");


        // cm_old: COMM(s_old | COMM(r_old | a_old_pk | p_old) | v_old)
        Wire[] tmp_cm_old = new Wire[1 + hashDigestDimension + 1];
        tmp_cm_old[0] = r;
        for(int i=0; i<hashDigestDimension; i++) { tmp_cm_old[i+1] = a_old_pk[i]; }
        tmp_cm_old[hashDigestDimension+1] = p;
        sha2Gadget = new SHA256Gadget(tmp_cm_old, 32, 36, false, true); // 32 bytes + 4 bytes
		cm_old = sha2Gadget.getOutputWires();

        tmp_cm_old = new Wire[1 + hashDigestDimension + 1];
        tmp_cm_old[0] = s;
        for(int i=0; i<hashDigestDimension; i++) { tmp_cm_old[i+1] = cm_old[i]; }
        tmp_cm_old[hashDigestDimension+1] = v;
        sha2Gadget = new SHA256Gadget(tmp_cm_old, 32, 36, false, true); // 32 bytes + 4 bytes
		cm_old = sha2Gadget.getOutputWires();
        makeOutputArray(cm_old, "cm_old");


        // cm_new: COMM(s_new | COMM(r_new | a_new_pk | p_new) | v_new)
        Wire[] tmp_cm_new = new Wire[1 + hashDigestDimension + 1];
        tmp_cm_new[0] = r;
        for(int i=0; i<hashDigestDimension; i++) { tmp_cm_new[i+1] = a_new_pk[i]; }
        tmp_cm_new[hashDigestDimension+1] = p;
        sha2Gadget = new SHA256Gadget(tmp_cm_new, 32, 36, false, true); // 32 bytes + 4 bytes
		cm_new = sha2Gadget.getOutputWires();

        tmp_cm_new = new Wire[1 + hashDigestDimension + 1];
        tmp_cm_new[0] = s;
        for(int i=0; i<hashDigestDimension; i++) { tmp_cm_new[i+1] = cm_new[i]; }
        tmp_cm_new[hashDigestDimension+1] = v;
        sha2Gadget = new SHA256Gadget(tmp_cm_new, 32, 36, false, true); // 32 bytes + 4 bytes
		cm_new = sha2Gadget.getOutputWires();
        makeOutputArray(cm_new, "cm_new");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        circuitEvaluator.setWireValue(v, new BigInteger("118")); // Random Value
        circuitEvaluator.setWireValue(p, new BigInteger("112")); // Random Value
        circuitEvaluator.setWireValue(r, new BigInteger("114")); // Random Value
        circuitEvaluator.setWireValue(s, new BigInteger("115")); // Random Value

        for(int i=0; i<hashDigestDimension; i++) {
            circuitEvaluator.setWireValue(a_old_sk[i], new BigInteger("97111112"));
            circuitEvaluator.setWireValue(a_new_sk[i], new BigInteger("97110112"));
        }
	}

	public static void main(String[] args) throws Exception {
		ZcashInitCircuitGenerator generator = new ZcashInitCircuitGenerator("zcash_init");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}