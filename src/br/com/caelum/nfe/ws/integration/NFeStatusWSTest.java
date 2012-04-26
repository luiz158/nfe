package br.com.caelum.nfe.ws.integration;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Holder;
import javax.xml.ws.handler.Handler;

import br.com.caelum.nfe.HSKeyManager;
import br.com.caelum.nfe.SOAPLoggingHandler;
import br.com.caelum.nfe.ws.sp.NfeCabecMsg;
import br.com.caelum.nfe.ws.sp.NfeDadosMsg;
import br.com.caelum.nfe.ws.sp.NfeStatusServico2;
import br.com.caelum.nfe.ws.sp.NfeStatusServico2Soap12;
import br.com.caelum.nfe.ws.sp.NfeStatusServicoNF2Result;
import br.com.caelum.nfe.ws.sp.ObjectFactory;
import br.com.caelum.nfe.xsd.schema.generated.TConsStatServ;

public class NFeStatusWSTest {
	private static final boolean DEBUG_ENABLE = false;
	private static final boolean LOG_ENABLE = false;

	private static String configName = "token.cfg";
	private static String senhaDoCertificado = "we#c$a";
	private static String arquivoCacertsGeradoTodosOsEstados = "NFeCacerts";
	private static String alias = "le-3a3c8936-b792-42f5-af7d-2b398bd7ce50";
//	private static String alias = "neuron tecnologia em informatica ltda:09661762000103";
//	private static String alias = "neuron tecnologia em informatica ltda:09661762000103 1";
//	private static String alias = "neuron tecnologia em informatica ltda:09661762000103 2";

	public static void main(String[] args) {
		try {

//			//obtém o keystore com os certificados
//			 KeyStore ks = KeyStore.getInstance("KeychainStore", "Apple");
//			 ks.load(null);
//
			KeyStore ks = getLocalKeyStore();
//
			X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, senhaDoCertificado.toCharArray());
//
//			//habilita o ssl para os webservices
			enableSSLForWS(certificate, privateKey);

			//======================================================================================
			//webservice
			NfeStatusServico2Soap12 consulta = new NfeStatusServico2().getNfeStatusServico2Soap12();

			// configura os loggers / debug (habilitar lá em cima)
			configureDebug();
			configureLoggiing((BindingProvider) consulta);

			//=======================================================================================

			//factories de objetos do ws e dos xsds
			ObjectFactory objectFactoryWS = new ObjectFactory();
			br.com.caelum.nfe.xsd.schema.generated.ObjectFactory objectFactoryXSD = new br.com.caelum.nfe.xsd.schema.generated.ObjectFactory();

			//cabecalho da msg do ws
			NfeCabecMsg cabec = objectFactoryWS.createNfeCabecMsg();
			cabec.setCUF("35");
			cabec.setVersaoDados("2.00");
			Holder<NfeCabecMsg> holderCab = new Holder<NfeCabecMsg>(cabec);

			//parte de dados da msg do ws
			NfeDadosMsg dados = objectFactoryWS.createNfeDadosMsg();

			//conteúdo da msg do ws
			TConsStatServ status = new TConsStatServ();
			status.setCUF("35");
			status.setTpAmb("2");
			status.setVersao("2.00");
			status.setXServ("STATUS");

			String xml = getXMLSniptlet(status);
			System.out.println(xml);
//			dados.getContent().add(new JAXBElement<String>(new QName(""),String.class,xml));

			//adicionando o conteúdo no obj de dados do ws
			dados.getContent().add(objectFactoryXSD.createConsStatServ(status));

			//imprimindo para ver...
			System.out.println("REQUEST==========>");
			printXML(dados);

//			//chamando o webservice e pegando o resultado
			NfeStatusServicoNF2Result result = consulta.nfeStatusServicoNF2(dados, holderCab);
//
//			//imprimindo o resultado...
			System.out.println("RESPONSE==========>");
			printXML(result);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static String getXMLSniptlet(Object dados) throws JAXBException {
		// TODO Auto-generated method stub
		 Marshaller marshaller = getMarshallerFor(dados.getClass());
		 marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,  Boolean.TRUE);
		 marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);

		 ByteArrayOutputStream os = new ByteArrayOutputStream();
		 JAXBElement<TConsStatServ> bla = new JAXBElement<TConsStatServ>(new QName("http://www.portalfiscal.inf.br/nfe", "consStatServ"), TConsStatServ.class, (TConsStatServ) dados);

		 marshaller.marshal(bla, os);

		 return os.toString().trim();
	}

	private static void printXML(Object dados) throws PropertyException, JAXBException {
		 Marshaller marshaller = getMarshallerFor(dados.getClass());
		 marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT,  Boolean.TRUE);

		 marshaller.marshal(dados, System.out);
	}

	private static Marshaller getMarshallerFor(Class<?> klass) throws JAXBException, PropertyException {
		JAXBContext jaxContext = JAXBContext.newInstance(klass);
		 Marshaller marshaller = jaxContext.createMarshaller();
		return marshaller;
	}

	private static void configureLoggiing(BindingProvider bp) {
		if(LOG_ENABLE){
			List<Handler> handlerChain = bp.getBinding().getHandlerChain();
			handlerChain.add(new SOAPLoggingHandler());
			bp.getBinding().setHandlerChain(handlerChain);
		}
	}

	private static void enableSSLForWS(X509Certificate certificate, PrivateKey privateKey) throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, KeyManagementException {
		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(arquivoCacertsGeradoTodosOsEstados), "changeit".toCharArray());
		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(trustStore);

		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		KeyManager[] keyManagers = { new HSKeyManager(certificate, privateKey) };

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(keyManagers, trustManagers, null);

		HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
	}

	private static void configureDebug() {
		if(DEBUG_ENABLE){
			System.setProperty("javax.net.debug", "all");
			System.setProperty("com.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump", "true");
		}
	}

	private static KeyStore getLocalKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException {
		Provider p = new sun.security.pkcs11.SunPKCS11(configName);
		Security.addProvider(p);
		char[] pin = senhaDoCertificado.toCharArray();
		KeyStore ks = KeyStore.getInstance("pkcs11", p);
		ks.load(null, pin);
		return ks;
	}

}
