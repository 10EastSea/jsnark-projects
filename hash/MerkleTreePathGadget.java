package projects.hash;

import circuit.config.Config;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;
import examples.gadgets.hash.SHA256Gadget;


/**
 * A Merkle tree authentication gadget using the subsetsum hash function
 * 
 */

public class MerkleTreePathGadget extends Gadget {

	private static int digestWidth = 8;

	private int treeHeight;
	private Wire directionSelectorWire;
	private Wire[] directionSelectorBits;
	private Wire[] leafWires;
	private Wire[] intermediateHashWires;
	private Wire[] outRoot;

	private int leafWordBitWidth;

	public MerkleTreePathGadget(Wire directionSelectorWire, Wire[] leafWires, Wire[] intermediateHasheWires,
			int leafWordBitWidth, int treeHeight, String... desc) {

		super(desc);
		this.directionSelectorWire = directionSelectorWire;
		this.treeHeight = treeHeight;
		this.leafWires = leafWires;
		this.intermediateHashWires = intermediateHasheWires;
		this.leafWordBitWidth = leafWordBitWidth;

		buildCircuit();

	}

	private void buildCircuit() {
		directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray(); // 3 -> binary: 11 -> 2 bits => array size: 2
		// directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray(); // test code

		// Apply CRH to leaf data
		Wire[] leafBits = new WireArray(leafWires).getBits(leafWordBitWidth).asArray(); // 10 * 32 bits = 320 bits => array size: 320
		SHA256Gadget sha2GadgetLeaf = new SHA256Gadget(leafBits, 1, 40, false, true); // integer 4 bytes * 10 = 40 bytes
		Wire[] currentHash = sha2GadgetLeaf.getOutputWires();

		// Apply CRH across tree path guided by the direction bits
		for (int i = 0; i < treeHeight; i++) {
			Wire[] inHash = new Wire[2 * digestWidth];
            // a: currentHash, b: intermediateHash
			for (int j = 0; j < digestWidth; j++) {
				Wire temp = currentHash[j].sub(intermediateHashWires[i * digestWidth + j]);
				Wire temp2 = directionSelectorBits[i].mul(temp);
				inHash[j] = intermediateHashWires[i * digestWidth + j].add(temp2); // b + d(a-b)
			}
			for (int j = digestWidth; j < 2 * digestWidth; j++) {
				Wire temp = currentHash[j - digestWidth].add(intermediateHashWires[i * digestWidth + j - digestWidth]);
				inHash[j] = temp.sub(inHash[j - digestWidth]); // a - d(a-b)
			}

			Wire[] nextInputBits = new WireArray(inHash).getBits(32).asArray(); // BigInteger range: 32 bits => (32 bits * 8) * 2 = 512 bits => array size: 512
			SHA256Gadget sha2GadgetInter = new SHA256Gadget(nextInputBits, 1, 64, false, true); // 512 bits -div 8-> 64 bytes
		    currentHash = sha2GadgetInter.getOutputWires();
		}
		outRoot = currentHash;
	}

	@Override
	public Wire[] getOutputWires() {
		return outRoot;
	}

}
