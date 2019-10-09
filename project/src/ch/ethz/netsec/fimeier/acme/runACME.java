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

import ch.ethz.netsec.fimeier.acme.client.ACMEClientv2;
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


	public static String challengeType, dir, record, domain;
	public static boolean revoke=false;
	
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
					revoke = true;
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




		// needed to import the ca
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
		dnsServer.createARecord("example.com");



		System.out.println("Starting ACME-Client....");
		ACMEClientv2 acmeclient = new ACMEClientv2(challengeType, dir, record, domain, revoke);
		acmeclient.start();



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
