package ch.ethz.netsec.fimeier.acme;

import java.util.ArrayList;
import java.util.List;

import ch.ethz.netsec.fimeier.acme.client.ACMEClientv2;
import ch.ethz.netsec.fimeier.acme.dns.DNSServer;
import ch.ethz.netsec.fimeier.acme.http.HTTPServer;

public class runACME {

	public static int shutdownHttpPort = 5003;
	public static int challengeHttpPort = 5002;
	public static int certificateHttpsPort = 5001;
	public static int dnsPort = 10053;

	public static String ipAddress = "1.2.3.4";


	public static String acmeKeyStore = "acme_keystore";
	//Test
	public static String certFullPath = "certificates/testfolder/localhost.crt";
	public static String keystoreFullPath = "certificates/testfolder/keystore.jks";


	public static List<String> domainList = new ArrayList<String>();
	public static String challengeType, dir, record;
	public static boolean revoke=false;

	public static DNSServer dnsServer;
	public static HTTPServer challengeHttpsServer;
	public static HTTPServer certificateHttpsServer;


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
					String domain = args[i+1];
					domainList.add(domain);
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
		certificateHttpsServer = new HTTPServer(certificateHttpsPort, "cert");


		System.out.println("Starting http-Challenge-Server implementation....");
		challengeHttpsServer = new HTTPServer(challengeHttpPort, "challenge");



		System.out.println("Starting DNS-Dummy implementation....");
		dnsServer = new DNSServer();
		dnsServer.start();
		//dnsServer.createARecord("example.com");



		System.out.println("Starting ACME-Client....");
		ACMEClientv2 acmeclient = new ACMEClientv2(challengeType, dir, record, domainList, revoke);
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

		System.out.println("Calling shutdownHttp.server.stop(0)....");
		shutdownHttp.server.stop(0);
		
		System.out.println("Calling certificateHttpsServer.server.stop(0)....");
		certificateHttpsServer.server.stop(0);
		
		System.out.println("Calling challengeHttpsServer.server.stop(0)....");
		challengeHttpsServer.server.stop(0);
		
		System.out.println("Calling dnsServer.stop()....");
		dnsServer.stop();

		System.out.println("Everything closed!!! End of program....");


		return;	
	}

}
