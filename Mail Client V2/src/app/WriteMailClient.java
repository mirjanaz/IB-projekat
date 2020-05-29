package app;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.api.services.gmail.Gmail;
import java.security.KeyStore;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_FILE = "./data/KorisnikA.jks";
	private static final String KEY_STORE_PASS = "123";
	private static final String KEY_STORE_ALIAS = "korisnik b";

	
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            
            System.out.println("Insert body:");
            String body = reader.readLine();
            
            
            //Compression
            String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
            String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
            
            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
			
			
			//sifrovanje
			byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
			String ciphertextStr = Base64.encodeToString(ciphertext);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			
			//inicijalizacija za sifrovanje 
			IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
			aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
			
			byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
			String ciphersubjectStr = Base64.encodeToString(ciphersubject);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			
			
			//snimaju se bajtovi kljuca i IV.
	/*		JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
			JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());*/
			
			// ucitavanje KeyStore fajla
        	KeyStore keyStore = KeyStoreReader.readKeyStore(KEY_STORE_FILE, KEY_STORE_PASS.toCharArray());
        	// preuzimanje sertifikata iz KeyStore-a za zeljeni alias
    		Certificate certificate = KeyStoreReader.getCertificateFromKeyStore(keyStore, KEY_STORE_ALIAS);
    		
    		// preuzimanje javnog kljuca iz ucitanog sertifikata
    		PublicKey publicKey = KeyStoreReader.getPublicKeyFromCertificate(certificate);
    		
    		//Postavljamo providera, jer treba za RSA Enkripciji/Dekripciju
			Security.addProvider(new BouncyCastleProvider());
			
    		//kriptovanje poruke javnim kljucem
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, publicKey);
			//kriptovanje
			byte[] kriptotxt = rsaCipherEnc.doFinal(secretKey.getEncoded());
			System.out.println("Kriptovan text: " + Base64.encodeToString(kriptotxt));
			
				
			
			
			MailBody mb=new MailBody(ciphertextStr, Base64.encodeToString(ivParameterSpec1.getIV()), Base64.encodeToString(ivParameterSpec2.getIV()), Base64.encodeToString(kriptotxt));
			String mbtelo=mb.toCSV();
			

			
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mbtelo);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        	
        	
    		
    		
    		
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
}
