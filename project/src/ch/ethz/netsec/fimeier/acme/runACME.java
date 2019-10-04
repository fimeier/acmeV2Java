package ch.ethz.netsec.fimeier.acme;

import ch.ethz.netsec.fimeier.acme.dns.DNSServer;
import ch.ethz.netsec.fimeier.acme.http.HTTPServer;

public class runACME {

	public static int shutdownHttpPort = 5003;
	public static int certificateHttpsPort = 5001;
	public static int dnsPort = 10053;

	public static String ipAddress = "1.2.3.4";



	public static String certFullPath = "certificates/testfolder/localhost.crt";
	public static String keystoreFullPath = "certificates/testfolder/keystore.jks";


	public static String challengeType;
	public static String dir, record, domain, revoke;
	
	private static void acmeClient() {
		
		
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
					break;
				}
				case "--record":{
					record = args[i+1];
					System.out.println("record: "+record);
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
