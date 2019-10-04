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


	public static void main(String[] args) throws Exception {
		System.out.println("Starting ACME-Project....");


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







		System.out.println("Everything started....");
		System.out.println("Now waiting to close evertything....");

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
