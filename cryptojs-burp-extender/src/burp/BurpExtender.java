package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
	
	private String extName = "CryptoJS-Decrypt-Encrypt";
	private String tabName = "CryptoJS";
	
	public IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	public PrintWriter stdout;
    public PrintWriter stderr;
    
    private CryptoJS crypto;
    public String passphrase = "";
    public String paramName = "";
	
	public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks){
//		init extension metadata
		callbacks.setExtensionName(extName);
//		init stdout stderr
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);
//		keep a reference to our callbacks object
        this.callbacks = callbacks;
//        obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
//        register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);
        
//        init cryptoJS
        crypto = new CryptoJS(this);
        
//        test functionality
//        crypto.cryptoJStest();
        this.stdout.write(this.passphrase + this.paramName);
        this.stdout.flush();
        
//        add suite tab
        callbacks.addSuiteTab(new CryptoConfigTab(tabName, this));
    }
	
	private class CryptoJS {
		public PrintWriter stdout;
	    public PrintWriter stderr;
		
		public CryptoJS(BurpExtender burp) {
			this.stdout = burp.stdout;
			this.stderr = burp.stderr;
		}
		
//	    cryptoJS-compatible encrypt decrypt
		public String encrypt(String plaintext, String passphrase) {
//		cryptoJS-ish encryption
//		google "java encryption cryptoJS passphrase"
//		https://stackoverflow.com/questions/29151211/how-to-decrypt-an-encrypted-aes-256-string-from-cryptojs-using-java
//		in the "linked" section at the bottom
//		https://stackoverflow.com/questions/27220297/what-are-the-aes-parameters-used-and-steps-performed-internally-by-crypto-js-whi?noredirect=1&lq=1
//		in the accepted answer's code there is a variable name openSslFormattedCipherTextString
//		which is in the format of ciphertext outputted by cryptoJS
			
//		google "openssl encrypt cryptojs decrypt"
//		https://stackoverflow.com/questions/32654749/decrypt-openssl-aes-with-cryptojs
//		in the accepted answer description, it is stated that openssl format is
//		"Salted__" + salt + actual ciphertext
			
			int keySize = 8;
			int ivSize = 4;
			
			byte[] prefix = helpers.stringToBytes("Salted__");
			byte[] salt = this.random(8);
			byte[] javaKey = new byte[keySize * 4];
			byte[] javaIv = new byte[ivSize * 4];
			try {
				evpKDF(passphrase.getBytes("UTF-8"), keySize, ivSize, salt, javaKey, javaIv);
			} catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
				e.printStackTrace(this.stderr);
			}
			
			try {
				Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
				IvParameterSpec ivSpec = new IvParameterSpec(javaIv);
				aesCipherForEncryption.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(javaKey, "AES"), ivSpec);
				byte[] encrypted = aesCipherForEncryption.doFinal(plaintext.getBytes("UTF-8"));
				
//            format the ciphertext like openssl
				byte[] finalCiphertext = new byte[prefix.length + salt.length + encrypted.length];
//            add the cryptoJS "Salted__" prefix
				System.arraycopy(prefix, 0, finalCiphertext, 0, prefix.length);
//            add the salt after prefix
				System.arraycopy(salt, 0, finalCiphertext, prefix.length, salt.length);
//            add the actual ciphertext
				System.arraycopy(encrypted, 0, finalCiphertext, prefix.length + salt.length, encrypted.length);
				
				return helpers.base64Encode(finalCiphertext);
			}
			catch (Exception e) {
				e.printStackTrace(this.stderr);
			}
			
			return "failed to encrypt";
		}
		public String decrypt(String encrypted, String password) throws Exception {
//    	cryptoJS decryption
//    	google "cryptoJS aes passphrase to key"
//    	https://www.py4u.net/discuss/282619
//    	https://stackoverflow.com/questions/27220297/what-are-the-aes-parameters-used-and-steps-performed-internally-by-crypto-js-whi/27250883#27250883
			
			int keySize = 8;
			int ivSize = 4;
			
			// Start by decoding the encrypted string (Base64)
			// Here I used the Android implementation (other Java implementations might exist)
			// byte[] cipherText = Base64.decode(encrypted, Base64.DEFAULT);
			byte[] cipherText = Base64.getDecoder().decode(encrypted);
			
			// prefix (first 8 bytes) is not actually useful for decryption, but you should probably check that it is equal to the string "Salted__"
			byte[] prefix = new byte[8];
			System.arraycopy(cipherText, 0, prefix, 0, 8);
			// Check here that prefix is equal to "Salted__"
			
			// Extract salt (next 8 bytes)
			byte[] salt = new byte[8];
			System.arraycopy(cipherText, 8, salt, 0, 8);
			
			// Extract the actual cipher text (the rest of the bytes)
			byte[] trueCipherText = new byte[cipherText.length - 16];
			System.arraycopy(cipherText, 16, trueCipherText, 0, cipherText.length - 16);
			
//        get javakey and javaiv with cryptojs kdf
			byte[] javaKey = new byte[keySize * 4];
			byte[] javaIv = new byte[ivSize * 4];
			evpKDF(password.getBytes("UTF-8"), keySize, ivSize, salt, javaKey, javaIv);
			
//        use the javakey and javaiv from kdf for decryption
			Cipher aesCipherForEncryption = Cipher.getInstance("AES/CBC/PKCS5Padding");
			IvParameterSpec ivSpec = new IvParameterSpec(javaIv);
			aesCipherForEncryption.init(Cipher.DECRYPT_MODE, new SecretKeySpec(javaKey, "AES"), ivSpec);
			byte[] byteMsg = aesCipherForEncryption.doFinal(trueCipherText);
			
			return new String(byteMsg, "UTF-8");
		}
//  cryptoJS utils
		private byte[] evpKDF(byte[] password, int keySize, int ivSize, byte[] salt, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
			return evpKDF(password, keySize, ivSize, salt, 1, "MD5", resultKey, resultIv);
		}
		private byte[] evpKDF(byte[] password, int keySize, int ivSize, byte[] salt, int iterations, String hashAlgorithm, byte[] resultKey, byte[] resultIv) throws NoSuchAlgorithmException {
			int targetKeySize = keySize + ivSize;
			byte[] derivedBytes = new byte[targetKeySize * 4];
			int numberOfDerivedWords = 0;
			byte[] block = null;
			MessageDigest hasher = MessageDigest.getInstance(hashAlgorithm);
			while (numberOfDerivedWords < targetKeySize) {
				if (block != null) {
					hasher.update(block);
				}
				hasher.update(password);
				block = hasher.digest(salt);
				hasher.reset();
				
				// Iterations
				for (int i = 1; i < iterations; i++) {
					block = hasher.digest(block);
					hasher.reset();
				}
				
				System.arraycopy(block, 0, derivedBytes, numberOfDerivedWords * 4,
						Math.min(block.length, (targetKeySize - numberOfDerivedWords) * 4));
				
				numberOfDerivedWords += block.length/4;
			}
			
			System.arraycopy(derivedBytes, 0, resultKey, 0, keySize * 4);
			System.arraycopy(derivedBytes, keySize * 4, resultIv, 0, ivSize * 4);
			
			return derivedBytes; // key + iv
		}
		private byte[] random(int length) {
			byte[] salt = new byte[length];
			new SecureRandom().nextBytes(salt);
			return salt;
		}
		@SuppressWarnings("unused") // for debug
		private String bytesToHex(byte[] bytes) {
			char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
			char[] hexChars = new char[bytes.length * 2];
			for (int j = 0; j < bytes.length; j++) {
				int v = bytes[j] & 0xFF;
				hexChars[j * 2] = HEX_ARRAY[v >>> 4];
				hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
			}
			return new String(hexChars);
		}
//  cryptoJS functionality test
		@SuppressWarnings("unused")
		private void cryptoJStest() {
			String pt = "action=login&username=qwe&password=asd";
			String ct = "U2FsdGVkX1+GSZ1Gh70ejz4cWnmTVJS/n9PKGlCK0bOUI0CTeNuRFnod9oJ+HGUnhOp2RBOu97AJQftz5iEZETWzcJohXzl5+xnt1oPhX2c=";
			String passphrase = "wVeAM";
			try {
				this.stdout.println("test decrypt from cryptoJS ======\n\n");
				this.stdout.println(ct);
				this.stdout.println(this.decrypt(ct, passphrase));
				this.stdout.println("\n\ntest encrypt like cryptoJS ======");
				this.stdout.println(this.encrypt(pt, passphrase));
				this.stdout.println("\n\ntest encrypt + decrypt ==========");
				this.stdout.println(this.decrypt(this.encrypt(pt, passphrase), passphrase));
			} catch (Exception e) {
				e.printStackTrace(this.stderr);
			}
		}
		
	}
    
    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new CryptojsTab(controller, editable, this);
    }
    
//    the message editor tab
    class CryptojsTab implements IMessageEditorTab {
//    	https://github.com/PortSwigger/example-custom-editor-tab
    	private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        
        private CryptoJS crypto;
        private String passphrase;
        private String paramName;
        
        BurpExtender burp;

        public CryptojsTab(IMessageEditorController controller, boolean editable, BurpExtender b) {
            this.editable = editable;
            this.crypto = b.crypto;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
            this.passphrase = b.passphrase;
            this.paramName = b.paramName;
        }

		@Override
		public String getTabCaption() {
			return "CryptoJS";
		}

		@Override
		public Component getUiComponent() {
			return txtInput.getComponent();
		}

		@Override
		public boolean isEnabled(byte[] content, boolean isRequest) {
//			return isRequest && helpers.getRequestParameter(content, paramName) != null;
			return isRequest;
		}

//		what we see in our editor tab
		@Override
		public void setMessage(byte[] content, boolean isRequest) {
			if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                // retrieve the data parameter
                IParameter parameter = helpers.getRequestParameter(content, paramName);
                
                // decrypt the parameter value
                try {
//                	IResponseInfo respObj = helpers.analyzeResponse(content);
//                	byte[] headers = helpers.stringToBytes(respObj.getHeaders().toString());
                	byte[] decrypted = helpers.stringToBytes(crypto.decrypt(helpers.urlDecode(parameter.getValue()), passphrase));
                	
//                	byte[] editorText = new byte[headers.length + decrypted.length];
//                	System.arraycopy(headers, 0, editorText, 0, headers.length);
//                	System.arraycopy(decrypted, 0, editorText, headers.length, decrypted.length);
					txtInput.setText(decrypted);
				} catch (Exception e) {
					e.printStackTrace(this.burp.stderr);
					txtInput.setText(helpers.stringToBytes("Error happened" + e.getStackTrace().toString()));
				}
                txtInput.setEditable(editable);
            }
            
            // remember the displayed content
            currentMessage = content;
		}

		@Override
		public byte[] getMessage() {
			// determine whether the user modified the decrypted data
            if (txtInput.isTextModified())
            {
                // encrypt the data
                byte[] text = txtInput.getText();
                String input;
				try {
					input = helpers.urlEncode(crypto.encrypt(helpers.bytesToString(text), passphrase));
				} catch (Exception e) {
					e.printStackTrace();
					input = e.getStackTrace().toString();
				}
                
                // update the request with the new parameter value
				IRequestInfo info = helpers.analyzeRequest(currentMessage);
				if (info.getMethod() == "GET") {
					return helpers.updateParameter(currentMessage, helpers.buildParameter(paramName, input, IParameter.PARAM_URL));
				} else { // POST and any other methods
					return helpers.updateParameter(currentMessage, helpers.buildParameter(paramName, input, IParameter.PARAM_BODY));					
				}
            }
            else return currentMessage;
		}

		@Override
		public boolean isModified() {
			return txtInput.isTextModified();
		}

		@Override
		public byte[] getSelectedData() {
			return txtInput.getSelectedText();
		}
    	
    }

//    the suite tab
    class CryptoConfigTab implements ITab {
    	private String tabName;
    	BurpExtender burp;
    	
    	public CryptoConfigTab(String name, BurpExtender b) {
    		this.tabName = name;
    		this.burp = b;
    	}
    	
    	@Override
    	public String getTabCaption() {
    		return tabName;
    	}
    	
    	@Override
    	public Component getUiComponent() {
    		return new CryptoConfig(burp);
    	}
    }    
}
