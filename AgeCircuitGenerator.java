package projects;

import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.hash.SHA256Gadget;

public class AgeCircuitGenerator extends CircuitGenerator {

    private static final int AGE = 25;
    
	private Wire ageWitness;
    private Wire[] ageStrWitness;
	private Wire[] ageHashInput;

    private SHA256Gadget sha2Gadget;

    public AgeCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		ageWitness = createProverWitnessWire("age"); // witness
        ageStrWitness = createProverWitnessWireArray(Integer.toString(AGE).length(), "age string array"); // witness
		ageHashInput = createInputWireArray(8, "age hash array"); // input

        // fuction 1: age is greater than or equal 20
		Wire result = ageWitness.isGreaterThan(19, 32); // int bit width: 32

        // fuction 2: age hash equal H(age)
		sha2Gadget = new SHA256Gadget(ageStrWitness, 8, Integer.toString(AGE).length(), false, true);
		Wire[] digest = sha2Gadget.getOutputWires();
		// makeOutputArray(digest, "digest");

		for(int i=0; i<8; i++) { result = result.add(digest[i].isEqualTo(ageHashInput[i])); }
		makeOutput(result.isEqualTo(new BigInteger("9")), "result"); // output
	}

	@Override
	public void generateSampleInput(CircuitEvaluator circuitEvaluator) {
        // witness: age
		circuitEvaluator.setWireValue(ageWitness, AGE);

        // witness: age string
        for(int i=0; i<Integer.toString(AGE).length(); i++) {
            circuitEvaluator.setWireValue(ageStrWitness[i], Integer.toString(AGE).charAt(i));
        }
		
        // input: age hash (H(25))
		circuitEvaluator.setWireValue(ageHashInput[0], new BigInteger("3081070707"));
        circuitEvaluator.setWireValue(ageHashInput[1], new BigInteger("3447136044"));
        circuitEvaluator.setWireValue(ageHashInput[2], new BigInteger("1148008091"));
        circuitEvaluator.setWireValue(ageHashInput[3], new BigInteger("1687433398"));
        circuitEvaluator.setWireValue(ageHashInput[4], new BigInteger("1517644706"));
        circuitEvaluator.setWireValue(ageHashInput[5], new BigInteger("2030016492"));
        circuitEvaluator.setWireValue(ageHashInput[6], new BigInteger("2176544597"));
        circuitEvaluator.setWireValue(ageHashInput[7], new BigInteger("3001496937"));
	}

	public static void main(String[] args) throws Exception {
		AgeCircuitGenerator generator = new AgeCircuitGenerator("age_example");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}