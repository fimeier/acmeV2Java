package ch.ethz.netsec.fimeier.acme.http;



import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.util.HashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import ch.ethz.netsec.fimeier.acme.runACME;
import ch.ethz.netsec.fimeier.acme.cert.CertificatesForAcmeHelper;


public class HTTPServer {
	public static boolean shutdowneverything = false;

	public HttpServer server;


	private int serverPort = 8000;

	private String mode = "";


	/*
	 * State Variables
	 */
	//change this to a list/hashmap if needed
	public HashMap<String, String> challengeUrlContentMap = new HashMap<String, String>();
	//public String challengeUrl;
	//public String challengeContent;

	/*
	 * state for cert https
	 */
	private CertificatesForAcmeHelper certHelper;
	public int keySize;
	public KeyPairGenerator keyGen;
	public KeyPair keyPairForCerts;

	public HTTPServer(int port, String mode, CertificatesForAcmeHelper _certHelper) throws Exception {

		this.certHelper = _certHelper;

		this.serverPort = port;
		this.mode = mode;

		/*
		 * set fields for cert https
		 */
		keySize = certHelper.keySize;
		keyGen = certHelper.keyGen;
		keyPairForCerts = certHelper.keyPairForCerts;


		//SSLContext sslContext = SSLContext.getInstance("TLS");
		SSLContext sslContext = certHelper.createSslContext();
		server = HttpsServer.create(new InetSocketAddress(this.serverPort), 0);

		((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(sslContext) {
			@Override
			public void configure(HttpsParameters params) {
				try {
					// initialise the SSL context
					SSLContext c = getSSLContext();
					SSLEngine engine = c.createSSLEngine();
					params.setNeedClientAuth(false);
					params.setCipherSuites(engine.getEnabledCipherSuites());
					params.setProtocols(engine.getEnabledProtocols());

					// Set the SSL parameters
					SSLParameters sslParameters = c.getSupportedSSLParameters();
					params.setSSLParameters(sslParameters);

				} catch (Exception ex) {
					System.out.println("Failed to create HTTPS port");
					System.out.println(ex.getMessage());
				}
			}
		});



		server.createContext("/", new MyHandlerCert());
		server.setExecutor(null); // creates a default executor
		server.start();
	}

	//for cert mode: loads always the same locally signed cert
	public HTTPServer(int port, String mode) throws Exception {

		this.serverPort = port;
		this.mode = mode;

		switch (mode) {
		case "challenge": {
			server = HttpServer.create(new InetSocketAddress(this.serverPort), 0);
			server.createContext("/", new MyHandlerChallenge());
			server.setExecutor(null); // creates a default executor
			server.start();
			break;			
		}
		case "shutdown": {
			server = HttpServer.create(new InetSocketAddress(this.serverPort), 0);
			server.createContext("/", new MyHandlerShutdown());
			server.setExecutor(null); // creates a default executor
			server.start();
			break;
		}
		case "cert": {

			SSLContext sslContext = SSLContext.getInstance("TLS");
			server = HttpsServer.create(new InetSocketAddress(this.serverPort), 0);


			/* Mein environment
			 * 
			 * inspired by https://gist.github.com/idurucz/992d95296e39f02646456dc9fc908db8
			 * 
			 * openssl pkcs12 -export -out keystore.pkcs12 -inkey localhost.key -certfile localhost.ca-bundle -in localhost.crt
			 * keytool -v -importkeystore -srckeystore keystore.pkcs12 -srcstoretype PKCS12 -destkeystore keystore.jks -deststoretype pkcs12
			 */
			// initialise the keystore
			char[] password = "password".toCharArray();
			KeyStore ks = KeyStore.getInstance("PKCS12");
			FileInputStream fis = new FileInputStream(runACME.keystoreFullPath);
			ks.load(fis, password);

			// setup the key manager factory
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, password);

			// setup the trust manager factory
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(ks);

			// setup the HTTPS context and parameters
			sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(sslContext) {
				@Override
				public void configure(HttpsParameters params) {
					try {
						// initialise the SSL context
						SSLContext c = getSSLContext();
						SSLEngine engine = c.createSSLEngine();
						params.setNeedClientAuth(false);
						params.setCipherSuites(engine.getEnabledCipherSuites());
						params.setProtocols(engine.getEnabledProtocols());

						// Set the SSL parameters
						SSLParameters sslParameters = c.getSupportedSSLParameters();
						params.setSSLParameters(sslParameters);

					} catch (Exception ex) {
						System.out.println("Failed to create HTTPS port");
						System.out.println(ex.getMessage());
					}
				}
			});

			server.createContext("/", new MyHandlerCert());
			server.setExecutor(null); // creates a default executor
			server.start();
			break;


		}
		default: {
			System.out.println("Error unknown mode HTTPServer");	
		}
		}


	}

	public void sendResponse(HttpExchange t, String message) throws IOException {
		String response = message;

		if (message.equals("")) {
			t.sendResponseHeaders(200, -1);
		} else {
			byte[] resp = response.getBytes();
			t.sendResponseHeaders(200, resp.length);
			OutputStream os = t.getResponseBody();
			os.write(resp);
			os.close();
		}
	}


	class MyHandlerChallenge implements HttpHandler {

		public void handle(HttpExchange t) throws IOException {

			String reqMethod = t.getRequestMethod();
			String reqURI = t.getRequestURI().getPath().toString();
			System.out.println("MyHandlerChallenge: reqMethod=" + reqMethod + " reqURI=" + reqURI);

			String challengeUrl = "";
			String challengeContent = "";
			//	challengeUrlContentMap.put(filePath, keyAuthorization)
			if (reqMethod.equals("GET")&& challengeUrlContentMap.containsKey(reqURI)) {
				//if (reqMethod.equals("GET")&&reqURI.equals(challengeUrl)) {
				//String message = challengeContent;

				String message = challengeUrlContentMap.get(reqURI);
				System.out.println("MyHandlerChallenge: returning "+challengeUrl +" with content: "+challengeContent);

				sendResponse(t, message);
			}
			else {
				String message = "MyHandlerChallenge: not sure what you want by calling "+challengeUrl;
				System.out.println(message);
				sendResponse(t, message);
			}

		}
	}



	class MyHandlerShutdown implements HttpHandler {

		public void handle(HttpExchange t) throws IOException {

			String reqMethod = t.getRequestMethod();
			String reqURI = t.getRequestURI().getPath().toString();
			System.out.println("MyHandlerShutdown: reqMethod=" + reqMethod + " reqURI=" + reqURI);

			if (reqMethod.equals("GET")&&reqURI.equals("/shutdown")) {
				System.out.println("MyHandlerShutdown: setting shutdowneverything = true");

				//send byebye...
				String message = "Byebye...";
				sendResponse(t, message);
				shutdowneverything = true;
			}
			else {
				System.out.println("MyHandlerShutdown: not sure what you want... try http://localhost:5003/shutdown");
				String message = "MyHandlerShutdown: not sure what you want... try http://localhost:5003/shutdown";
				sendResponse(t, message);
			}

		}
	}


	class MyHandlerCert implements HttpHandler {

		public void handle(HttpExchange t) throws IOException {

			String reqMethod = t.getRequestMethod();
			String reqURI = t.getRequestURI().getPath().toString();
			System.out.println("MyHandlerCert: reqMethod=" + reqMethod + " reqURI=" + reqURI);

			if (reqMethod.equals("GET")&&reqURI.equals("/")) {
				System.out.println("MyHandlerCert: asking for /");

				String message = "";
				sendResponse(t, message);
			} else if (reqMethod.equals("GET")&&reqURI.equals("/shutdown")) {
				System.out.println("MyHandlerCert: setting shutdowneverything = true");

				//send byebye...
				String message = "Byebye...";
				sendResponse(t, message);
				shutdowneverything = true;
			}
			else {
				System.out.println("MyHandlerCert: not sure what you want... try http://localhost:5003/shutdown");
				String message = "MyHandlerCert: not sure what you want... try http://localhost:5003/shutdown";
				sendResponse(t, message);
			}

		}
	}
}



