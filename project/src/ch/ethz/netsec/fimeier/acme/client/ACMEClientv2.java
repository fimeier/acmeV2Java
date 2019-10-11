package ch.ethz.netsec.fimeier.acme.client;




import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

import ch.ethz.netsec.fimeier.acme.runACME;
import ch.ethz.netsec.fimeier.acme.cert.CertificatesForAcmeHelper;
import ch.ethz.netsec.fimeier.acme.http.HTTPServer;


public class ACMEClientv2 {


	/*
	 * Startparameters (compare constructor)
	 */
	private String challengeType;
	private URL dirUrl;
	private InetAddress ipForDomain;
	private List<String> domainList;
	private boolean revokeCertAfterObtained;

	/*
	 * directory parameters (compare getDirectory())
	 */
	private URL newNonce;
	private URL newAccount;
	private URL newOrder;
	private URL newAuthz;
	private URL revokeCert;
	private URL keyChange;
	private JsonValue meta;


	/*
	 * State variable
	 */
	private Boolean isWildCard = false;
	private String nonce;
	private String orders;
	private URL ordersURL;
	private String accountUrl;
	private JsonObject orderObject;
	private URL orderObjectLocation;
	private List<JsonValue> dnsChallengeJsonList;
	private List <JsonValue> httpChallengeJsonList;
	private Boolean readForFinalization = false;
	private Boolean readForDownload = false;
	private URL certDownloadUrl;
	String certificatePem;

	/*
	 * Crypto stuff
	 */
	private int keySize;
	private KeyPairGenerator keyGen;
	private KeyPair keyPair;

	/*
	 * Cert stuff
	 */
	private CertificatesForAcmeHelper certHelper;



	public String removeWildCard(String domain) {		
		return domain.replace("*.", "");
	}



	private String encodeBase64String(String input, Boolean addQuotationMarks) {
		String quotes = "";
		if (addQuotationMarks)
			quotes = "\"";
		byte[] inputBytes = input.toString().getBytes(StandardCharsets.UTF_8);
		return quotes+Base64.getUrlEncoder().withoutPadding().encodeToString(inputBytes)+quotes;

	}


	private String getNBigIntegerEncoded() {
		RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
		String nBigIntegerEncoded = convertBigIntegerToBase64String(pk.getModulus());

		//String nBigIntegerEncodedRef = BigEndianBigInteger.toBase64Url(pk.getModulus());

		return nBigIntegerEncoded;
	}

	private String getEBigIntegerEncoded() {
		RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
		String eBigIntegerEncoded = convertBigIntegerToBase64String(pk.getPublicExponent());
		return eBigIntegerEncoded;
	}

	private String removeQuotes(String input) {
		return input.substring(1, input.length()-1);
	}



	/*
	 * TODO Anpassen/verstehen
	 */
	private String convertBigIntegerToBase64String(BigInteger bInt) {
		byte[] twosComplementBytes = bInt.toByteArray();
		byte[] magnitude;

		if ((bInt.bitLength() % 8 == 0) && (twosComplementBytes[0] == 0) && twosComplementBytes.length > 1)
		{
			//magnitude = ByteUtil.subArray(twosComplementBytes, 1, twosComplementBytes.length - 1);

			byte[] magnitudeTemp = new byte[twosComplementBytes.length - 1];
			System.arraycopy(twosComplementBytes, 1, magnitudeTemp, 0, magnitudeTemp.length);
			magnitude = magnitudeTemp;
		}
		else
		{
			magnitude = twosComplementBytes;
		}
		//		Base64Url base64Url = new Base64Url();
		//		String sRef = base64Url.base64UrlEncode(magnitude);

		//Standard Java
		String s = Base64.getUrlEncoder().withoutPadding().encodeToString(magnitude);// Regular base64 encoder
		//String s = Base64.getUrlEncoder().withoutPadding().encodeToString(twosComplementBytes);// Regular base64 encoder

		//s = sRef;

		s = s.split("=")[0]; // Remove any trailing ’=’s
		s = s.replace('+', '-'); // 62nd char of encoding
		s = s.replace('/', '_'); // 63rd char of encoding

		return s;

		/*
		 * copied from RFC7515
		 * Appendix C. Notes on Implementing base64url Encoding without Padding
This appendix describes how to implement base64url encoding and
decoding functions without padding based upon standard base64
encoding and decoding functions that do use padding.
To be concrete, example C# code implementing these functions is shown
below. Similar code could be used in other languages.
static string base64urlencode(byte [] arg)
{
string s = Convert.ToBase64String(arg); // Regular base64 encoder
s = s.Split(’=’)[0]; // Remove any trailing ’=’s
s = s.Replace(’+’, ’-’); // 62nd char of encoding
s = s.Replace(’/’, ’_’); // 63rd char of encoding
return s;
}
static byte [] base64urldecode(string arg)
{
string s = arg;
s = s.Replace(’-’, ’+’); // 62nd char of encoding
s = s.Replace(’_’, ’/’); // 63rd char of encoding
switch (s.Length % 4) // Pad with trailing ’=’s
{
case 0: break; // No pad chars in this case
case 2: s += "=="; break; // Two pad chars
case 3: s += "="; break; // One pad char
default: throw new System.Exception(
"Illegal base64url string!");
}
return Convert.FromBase64String(s); // Standard base64 decoder
}
		 */
	}


	private JsonObject parseResponseIntoJson(HttpsURLConnection newACMEConnection) {
		BufferedReader newAccountResponse;
		try {
			newAccountResponse = new BufferedReader(new InputStreamReader(newACMEConnection.getInputStream()));
			JsonReader responseReader = Json.createReader(newAccountResponse);
			JsonObject responseJson = responseReader.readObject();
			return responseJson;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;

	}
	/*
	 * mode = POST or GET
	 */
	/*
	 * Todo: Probleme wie bad nonce können hier nicht gelöst werden, da nonce ausserhalb gesetzt wird
	 */
	private HttpsURLConnection acmeHTTPsConnection (URL resourceUrl, byte[] bytesToPutOnWire, String mode) {
		boolean reTry = true;

		int i = 0;
		while(reTry) {
			try {


				HttpsURLConnection newACMEConnection = (HttpsURLConnection) resourceUrl.openConnection();

				if (mode.equals("downloadCert")) {
					newACMEConnection.setRequestMethod("POST");
					newACMEConnection.setFixedLengthStreamingMode(bytesToPutOnWire.length);
					newACMEConnection.setRequestProperty("Accept", "application/pem-certificate-chain");
					newACMEConnection.setDoOutput(true);
				}

				if (mode.equals("POST")) {
					newACMEConnection.setRequestMethod(mode);
					newACMEConnection.setFixedLengthStreamingMode(bytesToPutOnWire.length);
					newACMEConnection.setRequestProperty("Accept", "application/json");
					newACMEConnection.setDoOutput(true);
				}

				if (mode.equals("GET")) {
					newACMEConnection.setRequestMethod(mode);
					newACMEConnection.setRequestProperty("Accept", "application/json");
				}

				newACMEConnection.setRequestProperty("Content-Type","application/jose+json");
				newACMEConnection.setRequestProperty("charset", "utf-8");
				newACMEConnection.setRequestProperty("Accept-Language", "en");

				newACMEConnection.connect();


				if (mode.equals("POST") || mode.equals("downloadCert")) {
					OutputStream outputStream = newACMEConnection.getOutputStream();
					outputStream.write(bytesToPutOnWire);
					outputStream.flush();
				}

				//always store the nonce
				nonce = newACMEConnection.getHeaderField("Replay-Nonce");

				newACMEConnection.getHeaderFields().forEach((key, headers) -> headers.forEach(value ->
				System.out.println("HEADER-DEBUGGIN "+key+":"+value)));


				//special case for cert download???
				if (mode.equals("downloadCert")) {
					return newACMEConnection;
				}

				//TODO ANPASSEN
				//baue das in json parser sein... der kann ja eigentlich auch den return code abfragen....
				if (newACMEConnection.getResponseCode()==400 || newACMEConnection.getResponseCode()==403) {
					System.out.println("------------------HTTP 400||403-----------------------");
					BufferedReader errorStream = new BufferedReader(new InputStreamReader(newACMEConnection.getErrorStream()));
					JsonReader responseReader = Json.createReader(errorStream);
					JsonObject responseJson = responseReader.readObject();
					String content = responseJson.toString();
					System.out.println("content="+content);

					i++;
					if (i==1) {
						System.out.println("#################################################################");
						System.out.println("#################################################################");
						System.out.println("#############ERROR too many retries##############################");
						System.out.println("#################################################################");
						System.out.println("#################################################################");
						System.out.println("#################################################################");

						reTry = false;
					}
					System.out.println("#################################################################");
					System.out.println("#################################################################");
					System.out.println("#############HTTP 400 Retrying.....##############################");
					System.out.println("#################################################################");
					System.out.println("#################################################################");
					System.out.println("#################################################################");


					//get a fresh nonce
					//getANonce();
				} else {
					return newACMEConnection;
				}


			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return null;

	}

	public String getSignatureAsString(String protectedPartAsString, String payloadPartAsString) {
		try {
			String signingInputStringistt = 
					encodeBase64String(protectedPartAsString, false)
					+"."
					+encodeBase64String(payloadPartAsString,false);

			//System.out.println("signingInputStringSoll:"+signingInputString);
			//System.out.println("signingInputStringistt:"+signingInputStringistt);

			//replace this
			byte[] signatureInput = signingInputStringistt.getBytes("US-ASCII");
			Signature digitalSignature = Signature.getInstance("SHA256withRSA");
			digitalSignature.initSign(keyPair.getPrivate());
			digitalSignature.update(signatureInput);

			byte[] signature = digitalSignature.sign(); 

			String signatureAsString = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
			return signatureAsString;
		}
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();

		}
		return "";
	}


	public byte[] getBytesToPutOnWire(String protectedPartAsString, String payloadPartAsString, String signatureAsString) {
		JsonObject newAccountJson = Json.createObjectBuilder()
				.add("protected", encodeBase64String(protectedPartAsString, false))
				.add("payload", encodeBase64String(payloadPartAsString,false))
				.add("signature", signatureAsString)
				.build();
		byte[] newAccountJsonAsByte = newAccountJson.toString().getBytes(StandardCharsets.UTF_8);
		return newAccountJsonAsByte;
	}


	public JsonObject createProtectedPartJwk(URL resourceUrl, JsonObject jwk) {
		return Json.createObjectBuilder()
				.add("url",resourceUrl.toString())
				.add("jwk", jwk)
				.add("nonce", nonce)
				.add("alg", "RS256")
				.build();
	}


	public JsonObject createProtectedPartKid(URL resourceUrl) {
		return Json.createObjectBuilder()
				.add("url",resourceUrl.toString())
				//.add("jwk", jwk)
				.add("kid", accountUrl) //TODO account-URL?
				.add("nonce", nonce)
				.add("alg", "RS256")
				.build();
	}

	public JsonObject createJwk() {
		//REMARK: Fields are in correct order for thumbprint https://tools.ietf.org/pdf/rfc7638.pdf 3.1
		return Json.createObjectBuilder()
				.add("e", getEBigIntegerEncoded())
				.add("kty",keyPair.getPublic().getAlgorithm())
				.add("n", getNBigIntegerEncoded())
				.build();
	}



	/*
	 * returns the open orders {"orders":[]}
	 * should be stored in orderObjectLocation by postNewOrder()
	 */
	public void postAsGetOrders() {
		URL resourceUrl = ordersURL;

		HttpsURLConnection connectionACME = postAsGet(resourceUrl);

		JsonObject responseJson = parseResponseIntoJson(connectionACME);

		System.out.println("postAsGetOrder(): "+responseJson);
		System.out.println("orderObjectLocation: "+orderObjectLocation);

	}

	//downloadCert
	public HttpsURLConnection postAsGetMode(URL resourceUrl, String mode) {
		try {

			JsonObject protectedPart = createProtectedPartKid(resourceUrl);

			String signatureAsString = getSignatureAsString(protectedPart.toString(), "");

			byte[] postAsGetJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), "", signatureAsString);

			HttpsURLConnection connectionACME = acmeHTTPsConnection (resourceUrl, postAsGetJsonAsByte, mode);

			return connectionACME;

		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}
		return null;
	}

	public HttpsURLConnection postAsGet(URL resourceUrl) {
		return postAsGetMode(resourceUrl, "POST");

	}



	/*
	 * required: String dirUrl, String recordIpForDomain, String domain
	 * optional: revoke (Default should be false)
	 */
	public ACMEClientv2(String _challengeType, String _dirUrl, String _recordIpForDomain, List<String> _domains, boolean _revoke) {

		challengeType = _challengeType;
		if (_domains.get(0).contains("*")) {
			System.out.println("WILDCARD Certs have to use dns01 as challenge. Overridding setting if it was http01!!!!!!!!");
			challengeType = "dns01";
			isWildCard = true;
		}
		try {
			dirUrl = new URL(_dirUrl);
		} catch (MalformedURLException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}		



		try {
			ipForDomain = InetAddress.getByName(_recordIpForDomain);
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//TODO Decide what to do :-)
		domainList = _domains;
		dnsChallengeJsonList = new ArrayList<JsonValue>();
		httpChallengeJsonList = new ArrayList<JsonValue>();

		revokeCertAfterObtained = _revoke;


		/*
		 * Initialize crypto stuff
		 */
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keySize = 2048;
			keyGen.initialize(keySize);
			keyPair = keyGen.generateKeyPair();

		}
		catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}

		/*
		 * cert stuff
		 */
		certHelper = new CertificatesForAcmeHelper();

	}

	public void start() throws Exception {

		getDirectory();


		getANonce();


		postNewAccount();

		postNewOrder();



		//postAsGetOrders();

		postAsGetAuthorizationResources();

		fullfillChallenge();


		try {
			while(!readForFinalization) {
				postAsGetOrderStatus();
				Thread.currentThread().sleep(1000);
			}

		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//		System.out.println("sleeping for 60 seconds.....");
		//		try {
		//			Thread.currentThread().sleep(5000);
		//
		//
		//		} catch (InterruptedException e) {
		//			// TODO Auto-generated catch block
		//			e.printStackTrace();
		//		}
		//		System.out.println("fertig sleeping for 60 seconds.....");



		finalizeNewOrder();

	

		try {
			while(!readForDownload) {
				postAsGetOrderStatus();
				Thread.currentThread().sleep(1000);
			}

		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		postAsGetDownloadCert();


		installCert();


		if (revokeCertAfterObtained)
			postRevokeCert();





		//Not needed helpers
		//allready received in postNewOrder().. but usefull if "lost"
		//postAsGetOrders();










	}

	public void getANonce() {
		//newNonce
		try {
			HttpsURLConnection nonceACMEConnection = (HttpsURLConnection) newNonce.openConnection();
			nonceACMEConnection.setRequestMethod("GET");

			nonceACMEConnection.setDoOutput(false);

			BufferedReader directoryResponse = new BufferedReader(new InputStreamReader(nonceACMEConnection.getInputStream()));
			nonce = nonceACMEConnection.getHeaderField("Replay-Nonce");

			System.out.println("getANonce(): "+ nonce);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	/*
	 * TODO
	 */
	public void postANonce() {

	}

	private void getDirectory() {
		try {

			HttpsURLConnection dirACMEConnection = (HttpsURLConnection) dirUrl.openConnection();
			dirACMEConnection.setRequestMethod("GET");
			dirACMEConnection.setDoOutput(false);

			BufferedReader directoryResponse = new BufferedReader(new InputStreamReader(dirACMEConnection.getInputStream()));



			JsonReader jsonReader = Json.createReader(directoryResponse);
			JsonObject jobject = jsonReader.readObject();


			newNonce = new URL(jobject.getString("newNonce"));
			System.out.println("newNonce="+newNonce.toString());

			newAccount = new URL(jobject.getString("newAccount"));
			System.out.println("newAccount="+newAccount.toString());

			newOrder = new URL(jobject.getString("newOrder"));
			System.out.println("newOrder="+newAccount.toString());

			if (jobject.containsKey("newAuthz")) {
				newAuthz = new URL(jobject.getString("newAuthz"));
				System.out.println("newAuthz="+newAccount.toString());
			}
			else {
				System.out.println("newAuthz= NOT AVAILABLE");
			}

			revokeCert = new URL(jobject.getString("revokeCert"));
			System.out.println("revokeCert="+newAccount.toString());

			keyChange = new URL(jobject.getString("keyChange"));
			System.out.println("keyChange="+newAccount.toString());

			if (jobject.containsKey("meta")) {
				meta = jobject.get("meta");
				System.out.println("meta="+meta.toString());
			}
			else {
				System.out.println("meta= NOT AVAILABLE");
			}



			System.out.println("responseString:\n"+jobject.toString());
			dirACMEConnection.disconnect();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


	}


	private void postNewAccount() {
		getANonce();

		try {
			List<URI> contacts = new ArrayList<>(); 
			contacts.add(new URI("mailto:cert-admin@example.org"));
			contacts.add(new URI("mailto:admin@example.org"));
			Boolean termsOfServiceAgreed = true;

			URL resourceUrl = newAccount;


			//payload
			JsonObject payloadPart = Json.createObjectBuilder()
					.add("contact", Json.createArrayBuilder().add("mailto:cert-admin@example.org").add("mailto:admin@example.org"))
					.add("termsOfServiceAgreed", true)
					.build();

			//Header and jwk
			JsonObject jwk = createJwk();

			JsonObject protectedPart = createProtectedPartJwk(resourceUrl, jwk);


			String signatureAsString = getSignatureAsString(protectedPart.toString(),payloadPart.toString());

			byte[] newAccountJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), payloadPart.toString(), signatureAsString);

			HttpsURLConnection newAccountACMEConnection = acmeHTTPsConnection (newAccount, newAccountJsonAsByte, "POST");

			//save account url
			accountUrl = newAccountACMEConnection.getHeaderField("Location");



			JsonObject responseJson = parseResponseIntoJson(newAccountACMEConnection);
			orders = responseJson.getString("orders");
			ordersURL = new URL(orders);

			System.out.println("newAccountResponse: "+responseJson);


		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}


	/*
POST /acme/new-order HTTP/1.1
Host: example.com
Content-Type: application/jose+json
{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "5XJ1L3lEkMG7tR6pA00clA",
"url": "https://example.com/acme/new-order"
}),
"payload": base64url({
"identifiers": [
{ "type": "dns", "value": "www.example.org" },
{ "type": "dns", "value": "example.org" }
],
"notBefore": "2016-01-01T00:04:00+04:00",
"notAfter": "2016-01-08T00:04:00+04:00"
}),
"signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
}
	 */
	private void postNewOrder() {
		getANonce();

		try {

			URL resourceUrl = newOrder;


			//payload

			//String domain = domainList.get(0);


			JsonArrayBuilder allDomainsJsonObject = Json.createArrayBuilder();

			for (String domain: domainList) {
				JsonObject ident = Json.createObjectBuilder().add("type","dns").add("value",domain).build();
				allDomainsJsonObject.add(ident);

			}

			JsonArrayBuilder identifiersArray = Json.createArrayBuilder().addAll(allDomainsJsonObject);

			JsonObject payloadPart = Json.createObjectBuilder()
					.add("identifiers",identifiersArray)
					.build();




			//			JsonObject payloadPart = Json.createObjectBuilder()
			//					.add("identifiers",Json.createArrayBuilder()
			//							.add(Json.createObjectBuilder().add("type","dns").add("value",domain).build())
			//							)
			//					.build();

			JsonObject protectedPart = createProtectedPartKid(resourceUrl);

			String signatureAsString = getSignatureAsString(protectedPart.toString(),payloadPart.toString());

			byte[] postAsGetJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), payloadPart.toString(), signatureAsString);

			HttpsURLConnection connectionACME = acmeHTTPsConnection (resourceUrl, postAsGetJsonAsByte, "POST");

			JsonObject responseJson = parseResponseIntoJson(connectionACME);
			orderObject = responseJson;

			orderObjectLocation = new URL(connectionACME.getHeaderField("Location"));

			System.out.println("postNewOrder(): "+responseJson);
			System.out.println("postNewOrder() orderObjectLocation: "+orderObjectLocation.toString());


		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	//	//POST-as-GET requests to the indicated URLs

	/*
	 * 	When a client receives an order from the server in reply to a
	 *	newOrder request, it downloads the authorization resources by sending
	 *	POST-as-GET requests to the indicated URLs.
	 *
		orderObject = {"status":"pending",
			"expires":"2019-10-10T11:36:34Z",
			"identifiers":[{"type":"dns","value":"example.com"}],
			"finalize":"https://127.0.0.1:14000/finalize-order/XSbrc_B88Hm-hxTUMn7QxW3jDCOHnxcaikrDpXbImio",
			"authorizations":["https://127.0.0.1:14000/authZ/MeqUJQCIlEqcPKEPVRnHIY9UZq6prlPisW-86NqAqNg"]
		}

	 */
	private void postAsGetAuthorizationResources() {
		getANonce();

		try {

			//ev mehrere Objekte im array

			for (JsonValue authJson: orderObject.get("authorizations").asJsonArray()){
				//				System.out.println("!!!!!authorizations-list"+a.toString());
				//			}
				//
				//			String authorizations = removeQuotes(orderObject.get("authorizations").asJsonArray().get(0).toString());

				String authorizations = removeQuotes(authJson.toString());
				System.out.println("authorizations="+authorizations);

				URL resourceUrl = new URL(authorizations);


				HttpsURLConnection connectionACME = postAsGet(resourceUrl);

				JsonObject responseJson = parseResponseIntoJson(connectionACME);

				System.out.println("postAsGetAuthorizationResources(): "+responseJson);

				/*
				 * 			postAsGetAuthorizationResources(): 
				 * {"status":"pending",
				 * "identifier":{"type":"dns","value":"example.com"},
				 * "challenges":[
				 * {"type":"tls-alpn-01","url":"https://127.0.0.1:14000/chalZ/JVe6-qnooSHWbdl0o4O3DvSFG62O5PIoAo6HlJPX4pE",
				 * 					"token":"CKYuYVcX2j-ATEwoY7IiWdXHm5-kXoWGtMBKxxA4-2k","status":"pending"},
				 * {"type":"dns-01","url":"https://127.0.0.1:14000/chalZ/dysNT8Xho1TiVLDczijJwCjY2EvRny30xvpz_a3tx7c",
				 * 					"token":"ppRMzz1zMEyICBoubIxGl84IUuWShyjZdwi5-RNpvIo","status":"pending"},
				 * {"type":"http-01","url":"https://127.0.0.1:14000/chalZ/9b-9q8vsMp7_d2kQSGhwt1S7V69eNlcfHjgZpneK-X8",
				 * 					"token":"ndUIWzdV3JZRfyOxE2j995vPuZWsEerbyEffEdPX4rE","status":"pending"}],
				 * "expires":"2019-10-09T13:14:13Z"}
				 * 
				 */

				for (JsonValue challenge: responseJson.get("challenges").asJsonArray()) {

					System.out.println("type="+((JsonObject) challenge).get("type").toString());

					if ( ((JsonObject) challenge).get("type").toString().equals("\"http-01\"") ){
						System.out.println("found challenge= "+challenge);
						JsonValue httpChallengeJson = challenge;
						httpChallengeJsonList.add(httpChallengeJson);
					}

					if ( ((JsonObject) challenge).get("type").toString().equals("\"dns-01\"") ){
						System.out.println("found challenge= "+challenge);
						JsonValue dnsChallengeJson = challenge;
						dnsChallengeJsonList.add(dnsChallengeJson);
					}

				}

			}



		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	public byte[] getSHA256AsBytes(String toHashedString) {
		byte[] thumbprintAsBytes = null;
		try {
			byte[] hashInputBytes = toHashedString.getBytes(StandardCharsets.UTF_8);//StringUtil.getBytesUtf8(jkwAsString);
			MessageDigest digestSHA256 = MessageDigest.getInstance("SHA-256");
			digestSHA256.update(hashInputBytes);
			thumbprintAsBytes = digestSHA256.digest();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return thumbprintAsBytes;
	}

	public String getSHA256AsString(String toHashedString) {
		String thumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(getSHA256AsBytes(toHashedString));
		return thumbprint;
	}


	public String getThumbPrint() {
		try {
			/*
		"e"
		 o "kty"
		 o "n"
			 */
			String jkwAsString = createJwk().toString();
			//n ost falsch codiert...

			//			byte[] hashInputBytes = jkwAsString.getBytes(StandardCharsets.UTF_8);//StringUtil.getBytesUtf8(jkwAsString);
			//			MessageDigest md = MessageDigest.getInstance("SHA-256");
			//			md.update(hashInputBytes);
			//			byte[] thumbprintAsBytes = md.digest();

			byte[] thumbprintAsBytes = getSHA256AsBytes(jkwAsString);


			//String thumbprint = base64UrlEncode(thumbprintAsBytes);
			//String thumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(thumbprintAsBytes);
			String thumbprint = getSHA256AsString(jkwAsString);

			//encodeBase64String(thumbprintAsBytes.g, false);

			//			
			//			String referenceTumbprint = base64UrlEncode(JoseUtils.thumbprint(keyPair.getPublic()));
			//			byte[] thumbprintAsBytesReference = JoseUtils.thumbprint(keyPair.getPublic());
			//			System.out.println("getThumbPrint(): referenceTumbprint="+referenceTumbprint);
			//			System.out.println("getThumbPrint(): thumbprint="+thumbprint);



			/*
			 * test
			 */
			//			byte[] sha256hash(String z) {
			//			 MessageDigest md = MessageDigest.getInstance("SHA-256");
			//	            md.update(z.getBytes("UTF-8"));
			//	            return md.digest();
			//			}
			//	            
			//			 String shit = base64UrlEncode(sha256hash(getAuthorization()));
			//			
			//			  public String getAuthorization() {
			//			        PublicKey pk = getLogin().getKeyPair().getPublic();
			//			        return getToken() + '.' + base64UrlEncode(JoseUtils.thumbprint(pk));


			return thumbprint;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return "";

	}

	public void fullfillChallenge() {
		System.out.println("fullfillChallenge(): starting...");
		getANonce();

		try {
			URL resourceUrl = null;
			String token = "";

			System.out.println("fullfillChallenge()fullfillChallenge()fullfillChallenge(): 1");

			List<JsonValue> challengeJsonList = null;
			if (challengeType.equals("dns01"))
				challengeJsonList = dnsChallengeJsonList;
			if (challengeType.equals("http01"))
				challengeJsonList = httpChallengeJsonList;

			//we need for all domains an A record
			for (String domain: domainList) {

				runACME.dnsServer.createARecord(removeWildCard(domain)); //createARecord
			}

			System.out.println("fullfillChallenge()fullfillChallenge()fullfillChallenge(): 2");


			int challengeNumber = 0;
			for (JsonValue challenge: challengeJsonList) {

				System.out.println("fullfillChallenge()fullfillChallenge()fullfillChallenge(): 3");

				String domain = removeWildCard(domainList.get(challengeNumber));

				System.out.println("fullfillChallenge()fullfillChallenge()fullfillChallenge(): 3");


				String challengeUrlAsString = removeQuotes(challenge.asJsonObject().get("url").toString());
				resourceUrl = new URL(challengeUrlAsString);
				token = removeQuotes(challenge.asJsonObject().get("token").toString());
				System.out.println("tokentokentokentokentokentokentoken="+token);
				String thumbprint = getThumbPrint();
				String keyAuthorization = token + '.' + thumbprint;

				System.out.println("fullfillChallenge()fullfillChallenge()fullfillChallenge(): 3");

				if (challengeType.equals("dns01")){
					System.out.println("dns01-challengeUrlAsString="+challengeUrlAsString);


					String hashOfKeyAuthorization = getSHA256AsString(keyAuthorization);
					//					System.out.println("fullfillChallenge(): keyAuthorization ="+keyAuthorization);
					//					System.out.println("fullfillChallenge(): keyAuthorization2="+hashOfKeyAuthorization);

					//for (String domain: domainList) {
					String challengeDomain = "_acme-challenge."+domain;
					runACME.dnsServer.createTxtRecord(challengeDomain, hashOfKeyAuthorization);
					//}

				} 


				if (challengeType.equals("http01")){
					System.out.println("http01-challengeUrlAsString="+challengeUrlAsString);
					/*
					 * The path at which the resource is provisioned is comprised of the
					fixed prefix "/.well-known/acme-challenge/", followed by the "token"
					value in the challenge. The value of the resource MUST be the ASCII
					representation of the key authorization.
					 */

					//2"create file on webserver" 
					// .well-known/acme-challenge/ + Token
					String filePath = "/.well-known/acme-challenge/" + token;
					//					System.out.println("@@@@@@@@@@@@@@@filePath="+filePath);
					//					System.out.println("@@@@@@@@@@@@@@@filePath="+filePath);
					//					System.out.println("@@@@@@@@@@@@@@@filePath="+filePath);

					//setting for webserver webserver
					//					runACME.challengeHttpsServer.challengeUrl = filePath;
					//					runACME.challengeHttpsServer.challengeContent = keyAuthorization;
					runACME.challengeHttpsServer.challengeUrlContentMap.put(filePath, keyAuthorization);
				}

				//payload ist "{}" <-FUCK YOU ACME...... 5h FUCK!!!! why not ""???? Fuck rfc... :-)
				JsonObject protectedPart = createProtectedPartKid(resourceUrl);

				String signatureAsString = getSignatureAsString(protectedPart.toString(),"{}");

				byte[] postAsGetJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), "{}", signatureAsString);

				HttpsURLConnection connectionACME = acmeHTTPsConnection (resourceUrl, postAsGetJsonAsByte, "POST");

				JsonObject responseJson = parseResponseIntoJson(connectionACME);

				System.out.println("fullfillChallenge(): "+responseJson);

				challengeNumber++;
			}
		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


	/*
Once the client believes it has fulfilled the server’s requirements,
it should send a POST request to the order resource’s finalize URL.
The POST body MUST include a CSR:
csr (required, string): A CSR encoding the parameters for the
certificate being requested [RFC2986]. The CSR is sent in the
base64url-encoded version of the DER format. (Note: Because this
field uses base64url, and does not include headers, it is
different from PEM.)
POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
Host: example.com
Content-Type: application/jose+json
{
"protected": base64url({
"alg": "ES256",
"kid": "https://example.com/acme/acct/evOfKhNU60wg",
"nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
"url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
}),
"payload": base64url({
"csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
}),
"signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
}
The CSR encodes the client’s requests with regard to the content of
the certificate to be issued. The CSR MUST indicate the exact same
set of requested identifiers as the initial newOrder request.
Identifiers of type "dns" MUST appear either in the commonName
portion of the requested subject name or in an extensionRequest
attribute [RFC2985] requesting a subjectAltName extension, or both.
(These identifiers may appear in any sort order.) Specifications
that define new identifier types must specify where in the
certificate signing request these identifiers can appear.

	POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
	Host: example.com
	Content-Type: application/jose+json
	{
	"protected": base64url({
	"alg": "ES256",
	"kid": "https://example.com/acme/acct/evOfKhNU60wg",
	"nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
	"url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
	}),
	"payload": base64url({
	"csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
	}),
	"signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
	}
	 */
	private void finalizeNewOrder() {
		getANonce();

		try {

			String finalizeURL = removeQuotes(orderObject.get("finalize").toString());
			System.out.println("finalizeURL="+finalizeURL);

			URL resourceUrl = new URL(finalizeURL);

			//!!! allenfalls anführungszeichen nötig
			String csrAsString = Base64.getUrlEncoder().withoutPadding().encodeToString(certHelper.createCSR(domainList));
			//payload
			JsonObject payloadPart = Json.createObjectBuilder()
					.add("csr",csrAsString)
					.build();


			//ok?
			JsonObject protectedPart = createProtectedPartKid(resourceUrl);

			String signatureAsString = getSignatureAsString(protectedPart.toString(),payloadPart.toString());

			byte[] postAsGetJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), payloadPart.toString(), signatureAsString);

			HttpsURLConnection connectionACME = acmeHTTPsConnection (resourceUrl, postAsGetJsonAsByte, "POST");

			JsonObject responseJson = parseResponseIntoJson(connectionACME);

			System.out.println("finalizeNewOrder(): "+responseJson);


		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	/*
	 * returns the status/details of orders orderObjectLocation
	 */
	public void postAsGetOrderStatus() {
		getANonce();


		URL resourceUrl = orderObjectLocation;

		HttpsURLConnection connectionACME = postAsGet(resourceUrl);

		JsonObject responseJson = parseResponseIntoJson(connectionACME);

		System.out.println("postAsGetOrderStatus(): "+responseJson);
		String status = responseJson.getString("status");

		switch(status) {
		case "ready":{

			//submitting finalization request
			readForFinalization = true;
			System.out.println("postAsGetOrderStatus(): status="+status + " => setting readForFinalization = true ... \"ready\": The server agrees that the requirements have been\n" + 
					"fulfilled, and is awaiting finalization. Submit a finalization\n" + 
					"request.");
			break;
		}
		case "valid":{
			readForDownload = true;
			System.out.println("postAsGetOrderStatus(): status="+status + " => setting readForDownload = true ... \"valid\": The server has issued the certificate and provisioned its\n" + 
					"URL to the \"certificate\" field of the order. Download the\n" + 
					"certificate.");
			try {
				certDownloadUrl = new URL(responseJson.getString("certificate"));
				System.out.println("postAsGetOrderStatus(): setting certDownloadUrl="+certDownloadUrl.toString());

			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			break;
		}
		case "invalid":{
			System.out.println("postAsGetOrderStatus(): status="+status + " => \"invalid\": The certificate will not be issued.\n" + 
					"order process abandoned.");
			break;
		}
		case "pending":{
			//TODO check pennding authorizations that need to be fullfilled
			System.out.println("postAsGetOrderStatus(): status="+status + " => \"pending\": The server does not believe that the client has\n" + 
					"fulfilled the requirements. Check the \"authorizations\" array for\n" + 
					"entries that are still pending.");
			break;
		}
		case "processing":{
			System.out.println("postAsGetOrderStatus(): status="+status + " => \"processing\": The certificate is being issued. Send a POST-as-GET\n" + 
					"request after the time given in the Retry-After header field of\n" + 
					"the response, if any.");
			//TODO get this Retry-After and USE it

			break;
		}
		default: {
			System.out.println("ERROR!!!!!!!!!!!! postAsGetOrderStatus(): status="+status + " => CASE NOT IMPLEMENTED");
			break;
		}
		}


	}

	public void postAsGetDownloadCert() {
		getANonce();
		try {


			URL resourceUrl = certDownloadUrl;

			HttpsURLConnection connectionACME = postAsGetMode(resourceUrl, "downloadCert");


			BufferedReader newAccountResponse = new BufferedReader(new InputStreamReader(connectionACME.getInputStream()));

			System.out.println("postAsGetDownloadCert(): Cert=\n");
			certificatePem = "";
			String inputLine = "";
			while((inputLine = newAccountResponse.readLine()) != null){
				certificatePem += "\n"+ inputLine;
			}
			//set it in the certHelper
			certHelper.certificatePem = certificatePem;
			System.out.println(certificatePem);


		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void installCert() throws Exception {
		//Stops the https server and restarts it with a new certificate

		runACME.certificateHttpsServer.server.stop(0);
		runACME.certificateHttpsServer = new HTTPServer(runACME.certificateHttpsPort, "cert", certHelper);
	}



	/*
	Example using an account key pair for the signature:
		POST /acme/revoke-cert HTTP/1.1
		Host: example.com
		Content-Type: application/jose+json
		{
		"protected": base64url({
		"alg": "ES256",
		"kid": "https://example.com/acme/acct/evOfKhNU60wg",
		"nonce": "JHb54aT_KTXBWQOzGYkt9A",
		"url": "https://example.com/acme/revoke-cert"
		}),
		"payload": base64url({
		"certificate": "MIIEDTCCAvegAwIBAgIRAP8...",
		"reason": 4
		}),
		"signature": "Q1bURgJoEslbD1c5...3pYdSMLio57mQNN4"
		}
	 */
	private void postRevokeCert() {
		getANonce();

		try {

			URL resourceUrl = revokeCert;



			//payload replace
			JsonObject payloadPart = Json.createObjectBuilder()
					.add("certificate",Base64.getUrlEncoder().withoutPadding().encodeToString(certHelper.certificateDer))
					.add("reason", 4)
					.build();

			JsonObject protectedPart = createProtectedPartKid(resourceUrl);

			String signatureAsString = getSignatureAsString(protectedPart.toString(),payloadPart.toString());

			byte[] postAsGetJsonAsByte = getBytesToPutOnWire(protectedPart.toString(), payloadPart.toString(), signatureAsString);

			HttpsURLConnection connectionACME = acmeHTTPsConnection (resourceUrl, postAsGetJsonAsByte, "POST");

			if (connectionACME.getResponseCode()==200) {
				System.out.println("postRevokeCert(): Revoked Certificate succesfully!!!!!");
			} else {
				BufferedReader errorStream = new BufferedReader(new InputStreamReader(connectionACME.getErrorStream()));
				JsonReader responseReader = Json.createReader(errorStream);
				JsonObject responseJson = responseReader.readObject();
				System.out.println("postRevokeCert(): "+responseJson);
			}

		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}




}
