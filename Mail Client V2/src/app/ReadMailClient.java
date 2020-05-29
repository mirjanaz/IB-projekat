package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.keystore.KeyStoreReader;
import model.mailclient.MailBody;
import support.MailHelper;
import support.MailReader;
import util.Base64;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	private static final String KEY_STORE_FILE = "./data/korisnikb.jks";
	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	private static final String KEY_STORE_PASS = "1234";
	private static final String KEY_STORE_ALIAS = "korisnikb";
	private static final String KEY_STORE_PASS_FOR_PRIVATE_KEY = "1234";

	
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
      //Izlistava prve PS mejlove prve stranice.
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
      //biranje mejla 
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
        //TODO: Decrypt a message and decompress it. The private key is stored in a file.
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5Padding");
	//	 SecretKey secretKey = new SecretKeySpec(JavaUtils.getBytesFromFile(KEY_FILE), "AES");
		//uyimamo poruku
		String str = MailHelper.getText(chosenMessage);
		//uzima se txt
		MailBody mb=new MailBody(str);
		String secretKeyStr =mb.getEncKey();
		KeyStore ks=KeyStoreReader.readKeyStore(KEY_STORE_FILE,KEY_STORE_PASS.toCharArray());
		
		// preuzimanje privatnog kljuca iz KeyStore-a za zeljeni alias
		PrivateKey privateKey = KeyStoreReader.getPrivateKeyFromKeyStore(ks, KEY_STORE_ALIAS, KEY_STORE_PASS_FOR_PRIVATE_KEY.toCharArray());
		
		
		try {
			
			//Postavljamo providera, jer treba za RSA Enkripciji/Dekripciju
			Security.addProvider(new BouncyCastleProvider());
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			
			rsaCipherEnc.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] secrectKeyByte= rsaCipherEnc.doFinal(Base64.decode(secretKeyStr));
			SecretKey secretKey=new SecretKeySpec(secrectKeyByte,"AES");
			
			String iv1Str=mb.getIV1();
//			byte[] iv1 = JavaUtils.getBytesFromFile(IV1_FILE);
			
			//vektor 1 koristimo jer nam treba za dekriptovanje tela poruke a iv 2 za subject
			
			IvParameterSpec ivParameterSpec1 = new IvParameterSpec(Base64.decode(iv1Str));
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec1);
			
		
			
			
			
			byte[] teloEN= Base64.decode(mb.getEncMessage());
			
			String receivedBodyTxt = new String(aesCipherDec.doFinal(teloEN));
			String decompressedBodyText = GzipUtil.decompress(Base64.decode(receivedBodyTxt));
			System.out.println("Body text: " + decompressedBodyText);
			
			
			//byte[] iv2 = JavaUtils.getBytesFromFile(IV2_FILE);
			String iv2Str=mb.getIV2();
			IvParameterSpec ivParameterSpec2 = new IvParameterSpec(Base64.decode(iv2Str));
			
			//inicijalizacija za dekriptovanje
			aesCipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec2);
			
			//dekompresovanje i dekriptovanje subject-a
			String decryptedSubjectTxt = new String(aesCipherDec.doFinal(Base64.decode(chosenMessage.getSubject())));
			String decompressedSubjectTxt = GzipUtil.decompress(Base64.decode(decryptedSubjectTxt));
			System.out.println("Subject text: " + new String(decompressedSubjectTxt));
			
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		
	}
	
}
