package projects.hash;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import projects.hash.MerkleTreePathGadget;

public class MTMSHA256CircuitGenerator extends CircuitGenerator {

	private Wire[] publicRootWires;
	private Wire[] intermediateHasheWires;
	private Wire directionSelector;
	private Wire[] leafWires;
	private int leafNumOfWords = 10;
	private int leafWordBitWidth = 32;
	private int treeHeight;
	private int hashDigestDimension = 8;

	private MerkleTreePathGadget merkleTreeGadget;
	
	public MTMSHA256CircuitGenerator(String circuitName, int treeHeight) {
		super(circuitName);
		this.treeHeight = treeHeight;
	}

	@Override
	protected void buildCircuit() {
		
		/** declare inputs **/
		
		publicRootWires = createInputWireArray(hashDigestDimension, "Input Merkle Tree Root");
		intermediateHasheWires = createProverWitnessWireArray(hashDigestDimension * treeHeight, "Intermediate Hashes");
		directionSelector = createProverWitnessWire("Direction selector");
		leafWires = createProverWitnessWireArray(leafNumOfWords, "Secret Leaf");

		/** connect gadget **/

		merkleTreeGadget = new MerkleTreePathGadget(
				directionSelector, leafWires, intermediateHasheWires, leafWordBitWidth, treeHeight);
		Wire[] actualRoot = merkleTreeGadget.getOutputWires();
		
		/** Now compare the actual root with the public known root **/
		Wire errorAccumulator = getZeroWire();
		for(int i = 0; i < hashDigestDimension; i++){
			Wire diff = actualRoot[i].sub(publicRootWires[i]);
			Wire check = diff.checkNonZero();
			errorAccumulator = errorAccumulator.add(check);
		}
		
		makeOutputArray(actualRoot, "Computed Root");
		
		/** Expected mismatch here if the sample input below is tried**/
		makeOutput(errorAccumulator.checkNonZero(), "Error if NON-zero");
		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
		// input: root
		circuitEvaluator.setWireValue(publicRootWires[0], new BigInteger("3229234860"));
		circuitEvaluator.setWireValue(publicRootWires[1], new BigInteger("4261587088"));
		circuitEvaluator.setWireValue(publicRootWires[2], new BigInteger("2478376568"));
		circuitEvaluator.setWireValue(publicRootWires[3], new BigInteger("4097056101"));
		circuitEvaluator.setWireValue(publicRootWires[4], new BigInteger("2687676531"));
		circuitEvaluator.setWireValue(publicRootWires[5], new BigInteger("3281229791"));
		circuitEvaluator.setWireValue(publicRootWires[6], new BigInteger("0751616963"));
		circuitEvaluator.setWireValue(publicRootWires[7], new BigInteger("1949075653"));
		
		// witness: direction selector
		circuitEvaluator.setWireValue(directionSelector, new BigInteger("3")); // 3 -> binary: 11 -> 2 bits
		// circuitEvaluator.setWireValue(directionSelector, Util.nextRandomBigInteger(treeHeight)); // test code

		// witness: co-path
		for(int i=0; i<hashDigestDimension; i++) { circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("1234567890")); }
		for(int i=hashDigestDimension; i<hashDigestDimension*2; i++) { circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("0987654321")); }
		// for(int i=0; i<hashDigestDimension*treeHeight; i++) { circuitEvaluator.setWireValue(intermediateHasheWires[i], new BigInteger("1234567890")); } // test code
		
		// witness: leaf node -> cm
		for(int i=0; i<leafNumOfWords; i++){ circuitEvaluator.setWireValue(leafWires[i], Integer.MAX_VALUE); }
	}
	
	public static void main(String[] args) throws Exception {
		MTMSHA256CircuitGenerator generator = new MTMSHA256CircuitGenerator("tree_2_sha256", 2);
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();		
	}
}
