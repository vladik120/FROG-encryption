package controller;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.util.Arrays;
import java.util.ResourceBundle;

import app.Data;
import app.Message;
import ecdsa.ECDSA;
import ecdsa.ECDSAdata;
import frog.FROG;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;
import rsa.RSA;
import rsa.publicKey;
import rsa.secretKey;

public class AppController implements Initializable {

	private int KEYSIZE = 6;
	private Data Alis;
	private Data Bob;
	private Message ToBob;
	private Message ToAlis;
	private ECDSAdata ecsdaData;

	@FXML
	private TextField AText;

	@FXML
	private TextField BText;

	@FXML
	private TextField NText;

	@FXML
	private TextField GxText;

	@FXML
	private TextField GyText;

	@FXML
	private TextField PrimerNum1Alis;

	@FXML
	private TextField PrimerNum2Alis;

	@FXML
	private TextField PublicKeyTextAlis;

	@FXML
	private Button SetRsaKeyAlisBtn;

	@FXML
	private TextField PlainTextAlis;

	@FXML
	private TextField EncryptetTextAlis;

	@FXML
	private TextField ReceivedTextAlis;

	@FXML
	private TextField DecryptedTextAlis;

	@FXML
	private Button EncryptTextAlisBtn;

	@FXML
	private Button SendAlisTextBtn;

	@FXML
	private Button DecryptTextAlisBtn;

	@FXML
	private Button ClearAlisBtn;

	@FXML
	private TextField PrimerNum1Bob;

	@FXML
	private TextField PrimerNum2Bob;

	@FXML
	private TextField PublicKeyTextBob;

	@FXML
	private Button SetRsaKeyBobBtn;

	@FXML
	private TextField PlainTextBob;

	@FXML
	private TextField EncryptetTextBob;

	@FXML
	private TextField ReceivedTextBob;

	@FXML
	private TextField DecryptedTextBob;

	@FXML
	private Button EncryptTextBobBtn;

	@FXML
	private Button SendBobTextBtn;

	@FXML
	private Button DecryptTextBobBtn;

	@FXML
	private Button ClearBobBtn;

	@FXML
	private TextField AlisPrivateKeyC;

	@FXML
	private TextField BobPrivateKeyC;

	@FXML
	void ClearAlis(ActionEvent event) {
		PlainTextAlis.clear();
		EncryptetTextAlis.clear();
		ReceivedTextAlis.clear();
		DecryptedTextAlis.clear();
	}

	@FXML
	void ClearBob(ActionEvent event) {
		PlainTextBob.clear();
		EncryptetTextBob.clear();
		ReceivedTextBob.clear();
		DecryptedTextBob.clear();
	}

	@FXML
	void DecryptTextAlis(ActionEvent event) {
		byte[] key;
		if (!ECDSA.checkSignature(ToAlis.getSign(), ecsdaData, Alis.getA(), ToAlis.getEncryptedKey())) {
			System.out.println("[AppController] the sign in Alis dec is " + Arrays.toString(ToAlis.getSign()));
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText("the message isnt from bob");
			errorAlert.showAndWait();

		}

		else {
			key = RSA.startRSADecryption(Alis.getMySecretKey(), ToAlis.getEncryptedKey());
			String plainString = new String(FROG.StartDecryption(ToAlis.getEncText(), key));
			DecryptedTextAlis.setText(plainString);
		}

	}

	@FXML
	void DecryptTextBob(ActionEvent event) {
		byte[] key;
		if (!ECDSA.checkSignature(ToBob.getSign(), ecsdaData, Bob.getA(), ToBob.getEncryptedKey())) {
			// System.out.println("[AppController] the sign in Bob dec is " +
			// Arrays.toString(ToBob.getSign()));
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText("the message isnt from Alis");
			errorAlert.showAndWait();
		}

		else {
			key = RSA.startRSADecryption(Bob.getMySecretKey(), ToBob.getEncryptedKey());
			// System.out.println("[AppController] the bob enc key is : " +
			// Arrays.toString(key));
			String plainString = new String(FROG.StartDecryption(ToBob.getEncText(), key));
			DecryptedTextBob.setText(plainString);
		}

	}

	@FXML
	void EncryptTextAlis(ActionEvent event) {
		byte[] key = FROG.makeKey(KEYSIZE);
		Alis.setMyKey(key);

		ToBob.setEncText(FROG.StartEncryption(PlainTextAlis.getText().getBytes(), Alis.getMyKey()));
		
		ToBob.setEncryptedKey(RSA.startRSAEncryption(Alis.getPublicFrom(), Alis.getMyKey()));
		
		

		ToBob.setSign(ECDSA.createSignature(ToBob.getEncryptedKey(), ecsdaData, Alis.getPrivateSignKey()));

		System.out.println("[AppController] Alis sign with " + Arrays.toString(ToBob.getSign()));

		EncryptetTextAlis.setText(new String(ToBob.getEncText()));
	}

	@FXML
	void EncryptTextBob(ActionEvent event) {
		byte[] key = FROG.makeKey(KEYSIZE);
		Bob.setMyKey(key);

		ToAlis.setEncryptedKey(RSA.startRSAEncryption(Bob.getPublicFrom(), Bob.getMyKey()));
		ToAlis.setEncText(FROG.StartEncryption(PlainTextBob.getText().getBytes(), Bob.getMyKey()));

		ToAlis.setSign(ECDSA.createSignature(ToAlis.getEncryptedKey(), ecsdaData, Bob.getPrivateSignKey()));

		System.out.println("[AppController] Bob sign with " + Arrays.toString(ToAlis.getSign()));

		EncryptetTextBob.setText(new String(ToAlis.getEncText()));

	}

	@FXML
	void SendAlisText(ActionEvent event) {
		ReceivedTextBob.setText(new String(ToBob.getEncText()));
	}

	@FXML
	void SendBobText(ActionEvent event) {
		ReceivedTextAlis.setText(new String(ToAlis.getEncText()));
	}

	@FXML
	void SetRsaKeyAlis(ActionEvent event) {
		int prime1 = Integer.parseInt(PrimerNum1Alis.getText());
		int prime2 = Integer.parseInt(PrimerNum2Alis.getText());
		int PB = Integer.parseInt(PublicKeyTextAlis.getText());

		Alis.setMyPublicKey(new publicKey(prime1, prime2, PB));
		Alis.setMySecretKey(new secretKey(prime1, prime2, PB));
		Bob.setPublicFrom(Alis.getMyPublicKey());

	}

	@FXML
	void SetRsaKeyBob(ActionEvent event) {
		int prime1 = Integer.parseInt(PrimerNum1Bob.getText());
		int prime2 = Integer.parseInt(PrimerNum2Bob.getText());
		int PB = Integer.parseInt(PublicKeyTextBob.getText());

		Bob.setMyPublicKey(new publicKey(prime1, prime2, PB));
		Bob.setMySecretKey(new secretKey(prime1, prime2, PB));
		Alis.setPublicFrom(Alis.getMyPublicKey());

	}

	@FXML
	void SetECDSA(ActionEvent event) {
		int a = Integer.parseInt(AText.getText());
		int b = Integer.parseInt(BText.getText());
		int n = Integer.parseInt(NText.getText());
		int Gx = Integer.parseInt(GxText.getText());
		int Gy = Integer.parseInt(GyText.getText());
		int AlisKey = Integer.parseInt(AlisPrivateKeyC.getText());
		int BobKey = Integer.parseInt(BobPrivateKeyC.getText());
		BigInteger[] tempBigIntegers;

		Alis.setPrivateSignKey(BigInteger.valueOf(AlisKey));
		Bob.setPrivateSignKey(BigInteger.valueOf(BobKey));

		ecsdaData = new ECDSAdata(a, b, n, BigInteger.valueOf(Gx), BigInteger.valueOf(Gy));

		if (ecsdaData.isFlag()) {
			tempBigIntegers = ECDSA.MultiPoint(ecsdaData.getN(), ecsdaData.getG(), BigInteger.valueOf(AlisKey),
					ecsdaData.getA());
			if (tempBigIntegers[0].equals(BigInteger.valueOf(0)) && tempBigIntegers[1].equals(BigInteger.valueOf(0))) {
				Alert errorAlert = new Alert(AlertType.ERROR);
				errorAlert.setHeaderText("Error!");
				errorAlert.setContentText("Alis public key in Eliptic Curve is ZERO");
				errorAlert.showAndWait();

			} else {
				Bob.setA(tempBigIntegers);
				tempBigIntegers = ECDSA.MultiPoint(ecsdaData.getN(), ecsdaData.getG(), BigInteger.valueOf(BobKey),
						ecsdaData.getA());
				if (tempBigIntegers[0].equals(BigInteger.valueOf(0))
						&& tempBigIntegers[1].equals(BigInteger.valueOf(0))) {
					Alert errorAlert = new Alert(AlertType.ERROR);
					errorAlert.setHeaderText("Error!");
					errorAlert.setContentText("Bob public key in Eliptic Curve is ZERO");
					errorAlert.showAndWait();
				} else {
					Alis.setA(tempBigIntegers);
					System.out.println("[AppController] successfully accomplish ECDSA");
					System.out.println("[AppController] Alis Public Point is " + Arrays.toString(Alis.getA()));
					System.out.println("[AppController] Bob Public Point is " + Arrays.toString(Bob.getA()));
				}
			}

		} else {
			Alert errorAlert = new Alert(AlertType.ERROR);
			errorAlert.setHeaderText("Error!");
			errorAlert.setContentText("the data curve is unvalid");
			errorAlert.showAndWait();
		}
	}

	public void start(Stage primaryStage) throws IOException {
		Parent root = FXMLLoader.load(getClass().getResource("/controller/app.fxml"));
		Scene scene = new Scene(root);

		primaryStage.setTitle("Cryptology Project");
		primaryStage.setScene(scene);
		primaryStage.show();

	}

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		Alis = new Data();
		Bob = new Data();
		ToAlis = new Message();
		ToBob = new Message();
	}

}
