package ch.ethz.netsec.fimeier.acme.dns;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import ch.ethz.netsec.fimeier.acme.runACME;

/*
 * 
TODO: Shutdown/interruptverhalten prüfen.... siehe socked return

nslookup
server 127.0.0.1
set port=10053
set type=a

 */

public class DNSServer {

	static volatile boolean shutdowneverything = false;
	
	private Thread dnsThread;


	private int dnsPort = runACME.dnsPort;

	DatagramSocket dnsSocket;

	private static final long TTL = 300L;

	private HashMap<String, String> txtRecords = new HashMap<>();
	private Map<String, InetAddress> aRecords = new HashMap<>();


	public DNSServer(){
		try {
			dnsSocket = new DatagramSocket(dnsPort);
		} catch (SocketException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void start() {
		dnsThread = new Thread(new MyDNSHandler());
		dnsThread.start();
	}
	

	public void stop() {
		shutdowneverything = true;
		dnsThread.interrupt();
		dnsSocket.close();
		dnsThread = null;		
	}


	public void createTxtRecord(String domain, String txt) {
		txtRecords.put(domain.replaceAll("\\.$", ""), txt);
	}

	public void createARecord(String domain){
		try {
			aRecords.put(domain.replaceAll("\\.$", ""), InetAddress.getByName(runACME.ipAddress));
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public class MyDNSHandler implements Runnable {
		@Override
		public void run() {
			while (!shutdowneverything) {
				System.out.println("starting new dns run.....");

				byte[] inBuffer = new byte[512];

				// Read the question
				DatagramPacket packetIn = new DatagramPacket(inBuffer, 512);
				packetIn.setLength(512);
				try {
					dnsSocket.receive(packetIn);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					System.out.println("joining dns thread....");
					return;
				}
				Message msg = null;
				try {
					msg = new Message(inBuffer);
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				Header header = msg.getHeader();

				Record question = msg.getQuestion();
				
//				System.out.println("DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS... ");
//				System.out.println("DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS... ");
//				System.out.println("DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS... ");
//				System.out.println("DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS...DNS... ");


				// Prepare a response
				Message response = new Message(header.getID());
				response.getHeader().setFlag(Flags.QR);
				response.addRecord(question, Section.QUESTION);

				Name name = question.getName();

				String txt = txtRecords.get(name.toString(true));
				if (question.getType() == Type.TXT && txt != null) {
					response.addRecord(new TXTRecord(name, DClass.IN, TTL, txt), Section.ANSWER);
				}

				InetAddress a = aRecords.get(name.toString(true));
				if (question.getType() == Type.A && a != null) {
					response.addRecord(new ARecord(name, DClass.IN, TTL, a), Section.ANSWER);
				}
				
//				System.out.println("MyDNSHandler():"+response.toString());

				byte[] outBuffer = response.toWire();
				DatagramPacket packet = new DatagramPacket(outBuffer, outBuffer.length, packetIn.getAddress(), packetIn.getPort());
				try {
					dnsSocket.send(packet);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			System.out.println("DNSServer: shutting down.... byebye");
		}
	}








}