package projects.elgamal;

import java.math.BigInteger;

import util.Util;
import circuit.config.Config;
import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;

import projects.elgamal.ElGamalEncryptionGadget;

public class ElGamalCircuitGenerator extends CircuitGenerator {

	private Wire M;
	private Wire g; // generator = 5
	private Wire x; // sk = x
	private Wire y; // pk = g^x

	private Wire r;
	private Wire g_r;
	private Wire ciphertext;
	private Wire plaintext;

	private ElGamalEncryptionGadget elgamalEncryptionGadget;
	private ElGamalDecryptionGadget elgamalDecryptionGadget;

	public ElGamalCircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		/* Input */
		M = createProverWitnessWire("Message");
		g = createInputWire("Generator"); // Public argument
		x = createProverWitnessWire("Secret Key");
		y = createInputWire("Public Key"); // Public argument

		makeOutput(M, "Message"); // 임시로 출력
		makeOutput(g, "Generator"); // 임시로 출력
		makeOutput(x, "Secret Key"); // 임시로 출력
		makeOutput(y, "Public Key"); // 임시로 출력


		/* Encryption */
		elgamalEncryptionGadget = new ElGamalEncryptionGadget(M, g, y, oneWire); // oneWire: dummy data

		r = elgamalEncryptionGadget.getR();
		g_r = elgamalEncryptionGadget.getGOfR();
		ciphertext = elgamalEncryptionGadget.getOutputWires()[0]; // 0번째 위치에 ciphertext 저장되어 있음
		
		makeOutput(r, "Random r"); // 임시로 출력
		makeOutput(g_r, "c1: g^r");
		makeOutput(ciphertext, "c2: Cipher Text");


		/* Decryption */
		elgamalDecryptionGadget = new ElGamalDecryptionGadget(g_r, ciphertext, x, oneWire); // oneWire: dummy data

		plaintext = elgamalDecryptionGadget.getOutputWires()[0]; // 0번째 위치에 plaintext 저장되어 있음

		makeOutput(plaintext, "Plain Text");
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		evaluator.setWireValue(M, new BigInteger("980522"));
		evaluator.setWireValue(g, new BigInteger("5"));

		// Public Key: x = 임의의 랜덤 값 (ex. x = 10)
		// Secret Key: y = g^x (ex. g^x = 5^10 = 9765625)
		evaluator.setWireValue(x, new BigInteger("65537"));
		evaluator.setWireValue(y, new BigInteger("4419190821368873468698544218915959266395949671068483497544284424391127985607")); // g^x (mod FIELD_PRIME) = (5^65537) % 21888242871839275222246405745257275088548364400416034343698204186575808495617
	}

	public static void main(String[] args) throws Exception {
		ElGamalCircuitGenerator generator = new ElGamalCircuitGenerator("elgamal");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
	
}
