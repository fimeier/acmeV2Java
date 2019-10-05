package ch.ethz.netsec.fimeier.acme;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import ch.ethz.netsec.fimeier.acme.dns.DNSServer;
import ch.ethz.netsec.fimeier.acme.http.HTTPServer;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;

public class runACME {

	public static int shutdownHttpPort = 5003;
	public static int certificateHttpsPort = 5001;
	public static int dnsPort = 10053;

	public static String ipAddress = "1.2.3.4";


	public static String acmeKeyStore = "acme_keystore";
	//Test
	public static String certFullPath = "certificates/testfolder/localhost.crt";
	public static String keystoreFullPath = "certificates/testfolder/keystore.jks";


	public static String challengeType;
	public static String dir, record, domain, revoke;

	//The acme-server's directory
	private static URI dirUri = null;
	private static Socket dirSocket = null;
	private static PrintWriter dirSocketoutPrintWriter;
	private static BufferedReader dirSocketinBufferedReader;

	private static void acmeClient() {
		//get acme-server config aka directory
		try {
			//dirSocket = new Socket(dirUri.getHost(),dirUri.getPort());

			/*

			SSLSocketFactory ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
			dirSocket = ssf.createSocket(dirUri.getHost(), dirUri.getPort());			
			System.out.println(dirUri.getHost()+"=host "+dirUri.getPort()+"=port "+dirSocket.isConnected()+"=istconnected");


			dirSocketoutPrintWriter = new PrintWriter(dirSocket.getOutputStream(), false);
			dirSocketinBufferedReader = new BufferedReader(new InputStreamReader(dirSocket.getInputStream()));
			 */

			/*
			dirSocketoutPrintWriter.println("GET / HTTP/1.1");
			dirSocketoutPrintWriter.println("Host: www.badunetworks.com");
			dirSocketoutPrintWriter.println("");
			dirSocketoutPrintWriter.flush();*/
			URL dirURL = dirUri.toURL();
			//HttpsURLConnection con = (HttpsURLConnection)dirURL;
			HttpsURLConnection dirACMEConnection = (HttpsURLConnection) dirURL.openConnection();
			// Add headers
			dirACMEConnection.setRequestMethod("GET");
			//dirACMEConnection.setRequestProperty(dir, "/dir");

			// Send data
			dirACMEConnection.setDoOutput(false);
			//DataOutputStream outputStream = new DataOutputStream(dirACMEConnection.getOutputStream());

			//String message = "directory";
			//byte[] resp = message.getBytes();

			//outputStream.write(resp);
			//outputStream.flush();
			//outputStream.close();
			BufferedReader directoryResponse = new BufferedReader(new InputStreamReader(dirACMEConnection.getInputStream()));

			/*
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
			 */


			JsonReader jsonReader = Json.createReader(directoryResponse);
			JsonObject jobject = jsonReader.readObject();

			/* https://tools.ietf.org/html/rfc8555#section-7.1.1
			 HTTP/1.1 200 OK
			   Content-Type: application/json
			
			   {
			     "newNonce": "https://example.com/acme/new-nonce",
			     "newAccount": "https://example.com/acme/new-account",
			     "newOrder": "https://example.com/acme/new-order",
			     "newAuthz": "https://example.com/acme/new-authz",
			     "revokeCert": "https://example.com/acme/revoke-cert",
			     "keyChange": "https://example.com/acme/key-change",
			     "meta": {
			       "termsOfService": "https://example.com/acme/terms/2017-5-30",
			       "website": "https://www.example.com/",
			       "caaIdentities": ["example.com"],
			       "externalAccountRequired": false
			     }
			   }
						 */
			URL newNonce = new URL(jobject.getString("newNonce"));
			System.out.println("newNonce="+newNonce.toString());
			
			URL newAccount = new URL(jobject.getString("newAccount"));
			System.out.println("newAccount="+newAccount.toString());
			
			URL newOrder = new URL(jobject.getString("newOrder"));
			System.out.println("newOrder="+newAccount.toString());
			
			if (jobject.containsKey("newAuthz")) {
				URL newAuthz = new URL(jobject.getString("newAuthz"));
				System.out.println("newAuthz="+newAccount.toString());
			}
			else {
				System.out.println("newAuthz= NOT AVAILABLE");
			}
			
			URL revokeCert = new URL(jobject.getString("revokeCert"));
			System.out.println("revokeCert="+newAccount.toString());

			URL keyChange = new URL(jobject.getString("keyChange"));
			System.out.println("keyChange="+newAccount.toString());



			//String responseString = response.toString();
			System.out.println("responseString:\n"+jobject.toString());
			dirACMEConnection.disconnect();

			//http://stackoverflow.com/a/15116323/4687348
			//JsonParser jsonParser = new JsonParser();
			//JsonObject object = (JsonObject)jsonParser.parse(responseString);

			//InputStream input = dirACMEConnection.getInputStream();
			//System.out.println(input.readAllBytes().toString());

			/*
			 * parse server config
			 *
			 */


		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}




	}


	private static void parseArguments(String[] args) {
		//System.out.println("args.length: "+ args.length);
		int i = 0;
		for (String arg: args) {
			//System.out.println("arg-"+i+": "+arg);

			if (i==0) {
				challengeType = args[0];
				System.out.println("Challenge type: "+challengeType);
			} 

			if (i%2==1) {
				switch(arg) {
				case "--dir":{
					dir = args[i+1];
					System.out.println("dir: "+dir);
					try {
						dirUri = new URI(dir);
					} catch (URISyntaxException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					break;
				}
				case "--record":{
					record = args[i+1];
					System.out.println("record: "+record);
					ipAddress = record;
					break;
				}
				case "--domain":{
					domain = args[i+1];
					System.out.println("domain: "+domain);
					break;
				}
				case "--revoke":{
					revoke = args[i+1];
					System.out.println("revoke: "+revoke);
					break;
				}


				default: {
					System.out.println("ERROR: Unknown argument given to runACME.main(), namely: " + arg);
				}
				}
			}
			i++;
		}
	}


	public static void main(String[] args) throws Exception {





		System.setProperty("javax.net.ssl.trustStore", acmeKeyStore);
		System.setProperty("javax.net.ssl.trustStorePassword", "password");




		System.out.println("Starting ACME-Project....");

		parseArguments(args);



		System.out.println("Starting Shutdown HTTP server on port "+shutdownHttpPort);
		HTTPServer shutdownHttp = new HTTPServer(shutdownHttpPort, "shutdown");



		System.out.println("Starting httpS-Dummy implementation....");
		HTTPServer certificateHttpsServer = new HTTPServer(certificateHttpsPort, "cert");

		//NotMyHTTPsServer certificateHttpsServer = new NotMyHTTPsServer();
		//certificateHttpsServer.main(certificateHttpsPort, keystoreFullPath);


		System.out.println("Starting DNS-Dummy implementation....");
		DNSServer dnsServer = new DNSServer();
		dnsServer.start();
		dnsServer.createARecord("fi.lip");



		System.out.println("Starting ACME-Client....");
		acmeClient();



		System.out.println("Everything started....");
		System.out.println("Now waiting to close everything....");

		//waiting to shutdown everything
		//stupid ad-hock implementation
		try {
			while(!HTTPServer.shutdowneverything) {
				Thread.sleep(100);
			}
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		shutdownHttp.server.stop(0);
		certificateHttpsServer.server.stop(0);
		dnsServer.stop();

		System.out.println("Everything closed!!! End of program....");


		return;	
	}

}
