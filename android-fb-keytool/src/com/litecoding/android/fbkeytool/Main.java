/* 
* Copyright 2012 Dmitry S. Vorobiev
*
*   Licensed under the Apache License, Version 2.0 (the "License");
*   you may not use this file except in compliance with the License.
*   You may obtain a copy of the License at
*
*       http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*   See the License for the specific language governing permissions and
*   limitations under the License.
*/


package com.litecoding.android.fbkeytool;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.UnrecoverableKeyException;

public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String keystore = null;
		String storepass = null;
		String keypass = null;
		String alias = null;
		
		if(args.length == 0) {
			usage();
			return;
		}
		
		int i = 0;
		while(i < args.length) {
			String arg = args[i];
			
			if(arg.equalsIgnoreCase("-keystore")) {
				i++;
				keystore = args[i];
			} else if(arg.equalsIgnoreCase("-storepass")) {
				i++;
				storepass = args[i];
			} else if(arg.equalsIgnoreCase("-alias")) {
				i++;
				alias = args[i];
			} else if(arg.equalsIgnoreCase("-keypass")) {
				i++;
				keypass = args[i];
			} else if(arg.equalsIgnoreCase("-h") || arg.equalsIgnoreCase("-help")) {
				usage();
				return;
			} else {
				error("Unknown argument - " + arg);
				return;
			}
			i++;
		}
		
		if(keystore == null) {
			error("Keystore path didn't specified");
			return;
		}
		
		if(alias == null) {
			error("Key alias didn't specified");
			return;
		}
		
		try {
			KeyStore store = KeyStore.getInstance("JKS");
			FileInputStream stream = new FileInputStream(keystore);
			
			try {
				store.load(stream, null);
			} catch(IOException e) {
				if(e.getCause() instanceof UnrecoverableKeyException) {
					try {
						store.load(stream, storepass.toCharArray());
					} catch(IOException ex) {
						error("Wrong keystore password");
						return;
					}
				}
				
			}
			
			KeyStore.Entry entry = null;
			try {
				entry = store.getEntry(alias, null);
			} catch(UnrecoverableKeyException e) {
				try {
					KeyStore.PasswordProtection password = new KeyStore.PasswordProtection(keypass.toCharArray());
					entry = store.getEntry(alias, password);
				} catch(UnrecoverableKeyException ex) {
					error("Wrong key password");
					return;
				}
				
			}
			
			if(entry == null) {
				error("No such entry (" + alias + ") in " + keystore);
				return;
			}
			
			if(entry instanceof KeyStore.PrivateKeyEntry) {
				byte cert[] = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getEncoded();
				
				MessageDigest digest = MessageDigest.getInstance("SHA-1");
				digest.update(cert);
				byte[] sha1Digest = digest.digest();
				
				System.out.println("Facebook key hash for " + alias + ": " + Base64.encodeBytes(sha1Digest));
			}
			
		} catch(FileNotFoundException e) {
			error("Generic error");
			e.printStackTrace();
		} catch(UnrecoverableKeyException e) { 
			//wrong key password, never should be catched here
			error("Generic error");
			e.printStackTrace();
		} catch(Exception e) {
			error("Generic error");
			e.printStackTrace();
		}

	}
	
	public static void usage() {
		System.out.println("Android FB keytool by Dmitry Vorobiev (http://litecoding.com/)");
		System.out.println("Command line arguments:");
		System.out.println("(similar to JDK keytool command line arguments)");
		System.out.println("-keystore <keystore> \t - path to keystore");
		System.out.println("-storepass <storepass> \t - (optional) keystore password");
		System.out.println("-alias <alias> \t - alias of key entry");
		System.out.println("-keypass <keypass> \t - (optional) key password");
		System.out.println();
		System.out.println("Enjoy!");
		System.out.println();
	}
	
	public static void error(String msg) {
		System.err.println("Error: " + msg);
	}

}
