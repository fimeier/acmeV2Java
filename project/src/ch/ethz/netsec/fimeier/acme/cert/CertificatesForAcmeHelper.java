package ch.ethz.netsec.fimeier.acme.cert;

import java.io.ByteArrayInputStream;
import java.net.IDN;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;


public class CertificatesForAcmeHelper {

	/*
	 * Crypto stuff
	 */
	public int keySize;
	public KeyPairGenerator keyGen;
	public KeyPair keyPairForCerts;

	/*
	 * state
	 */
	byte[] csrAsBytes = null;
	//ugly: set by ACMECLientvs.postAsGetDownloadCert() 
	public String certificatePem = "";



	public SSLContext createSslContext() throws Exception {

		String pem = certificatePem;
		Pattern parse = Pattern.compile("(?m)(?s)^---*BEGIN ([^-]+)---*$([^-]+)^---*END[^-]+-+$");
		Matcher m = parse.matcher(pem);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Decoder decoder = Base64.getMimeDecoder();
		List<Certificate> certList = new ArrayList<>();

		PrivateKey privateKey = keyPairForCerts.getPrivate();

		int start = 0;
		while (m.find(start)) {
			String type = m.group(1);
			String base64Data = m.group(2);
			byte[] data = decoder.decode(base64Data);
			start += m.group(0).length();
			type = type.toUpperCase();
			if (type.contains("CERTIFICATE")) {
				Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(data));
				certList.add(cert);
			}
			else {
				System.err.println("ERRRRRROR type unknown..... " + type);
			}

		}

		char[] keyStorePassword = new char[0];

		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);

		int count = 0;
		for (Certificate cert : certList) {
			keyStore.setCertificateEntry("cert" + count, cert);
			count++;
		}
		Certificate[] chain = certList.toArray(new Certificate[certList.size()]);
		keyStore.setKeyEntry("key", privateKey, keyStorePassword, chain);

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());//KeyManagerFactory.getInstance("RSA");
		kmf.init(keyStore, keyStorePassword);
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
		return sslContext;
	}

	public CertificatesForAcmeHelper() {

		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keySize = 2048;
			keyGen.initialize(keySize);
			keyPairForCerts = keyGen.generateKeyPair();
		}
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}

	}


	public byte[] createCSR(List<String> domains) {
		//the result
		csrAsBytes = null;
		try {
			
			X500NameBuilder nameBuilder = new X500NameBuilder(X500Name.getDefaultStyle());
			//List<String> alternativeNameList = new ArrayList<>();
			PKCS10CertificationRequest csr = null;

			//add all domains
			boolean isCommonName = true;
			int i = 0;
			GeneralName[] sanList = new GeneralName[domains.size()];
			for (String domain: domains) {
				String domainAsASCII = IDN.toASCII(domain.trim()).toLowerCase();
				//first domain is the common name
				if (isCommonName)
					nameBuilder.addRDN(BCStyle.CN, domainAsASCII);
				//all domains are added as SAN
				sanList[i] = new GeneralName(GeneralName.dNSName, domainAsASCII);
			}
		
			GeneralNames subjectAlternativeName = new GeneralNames(sanList);

			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(nameBuilder.build(), keyPairForCerts.getPublic());

			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
			extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeName);
			p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
			
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
			ContentSigner signer = csBuilder.build(keyPairForCerts.getPrivate());

			csr = p10Builder.build(signer);
			csrAsBytes = csr.getEncoded();
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return csrAsBytes;	
	}




}



