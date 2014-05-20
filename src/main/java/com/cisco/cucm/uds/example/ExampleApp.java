package com.cisco.cucm.uds.example;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.ProcessingException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;

import org.glassfish.jersey.client.ClientProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cisco.cucmws.pub.jaxb.clusteruser.get.JAXBGetClusterUser_ClusterUser;
import com.cisco.cucmws.pub.jaxb.clusteruser.get.JAXBGetClusterUser_HomeCluster;
import com.cisco.cucmws.pub.jaxb.servers.get.JAXBGetServers_Servers;

public class ExampleApp {
	private static final Logger LOG = LoggerFactory.getLogger(ExampleApp.class);

	private static final int CONNECT_TIMEOUT_MS = 1000;
	private static final int READ_TIMEOUT_MS = 1000;

	private static final String UDS_HOST = PropertyManager.getProperty("uds.host");
	private static final String UDS_SERVICE_URL = "https://" + UDS_HOST + ":8443/cucm-uds";

	private static final String CLUSTER_USER_URI = "/clusterUser";
	private static final String USERNAME = "username";

	private static String getUsername(final String[] args) {
		String username = "";
		if(args.length > 0) {
			username = args[0];
		}
		else {
			LOG.info("Username not provided, falling back to stdin");
			Scanner scanner = new Scanner(System.in);
			System.out.print("Please provide a username: ");
			username = scanner.nextLine();
			scanner.close();
		}

		return username;
	}

	public static void main(final String[] args) {
		String username = getUsername(args);

		Client client = getClient();

		try {
			// Perform a "cluster user" lookup to determine this user's home cluster
			WebTarget clusterUserTarget = client.target(UDS_SERVICE_URL).path(CLUSTER_USER_URI).queryParam(USERNAME, username);
			JAXBGetClusterUser_ClusterUser clusterUserJaxb = clusterUserTarget.request(MediaType.APPLICATION_XML).get(JAXBGetClusterUser_ClusterUser.class);
			if (clusterUserJaxb.getResult().isFound()) {
				JAXBGetClusterUser_HomeCluster homeClusterJaxb = clusterUserJaxb.getHomeCluster();
				LOG.info("Found user " + username + " on cluster " + homeClusterJaxb.getValue());

				// Look up the full list servers in the user's home cluster
				String serversUri = homeClusterJaxb.getServersUri();
				WebTarget serversTarget = client.target(serversUri);
				JAXBGetServers_Servers serversJaxb = serversTarget.request(MediaType.APPLICATION_XML).get(JAXBGetServers_Servers.class);

				System.out.println("Servers in home cluster:");
				for (String server : serversJaxb.getServers()) {
					LOG.info("\t* " + server);
				}
			} else {
				LOG.warn("Unable to find user " + username);
			}
		} catch (ProcessingException e) {
			LOG.error("HTTP request failed: " + e.getMessage(), e);
		}
	}

	private static Client getClient() {
		// Create a client instance with SSL certificate validation disabled
		Client client = ClientBuilder.newBuilder()
			.sslContext(getSSLContext())
			.hostnameVerifier(getHostnameVerifier())
			.build();

		// Adjust connection and read timeout
		client.property(ClientProperties.CONNECT_TIMEOUT, CONNECT_TIMEOUT_MS);
		client.property(ClientProperties.READ_TIMEOUT, READ_TIMEOUT_MS);

		return client;
	}

	/**
	 * Provides an SSLContext that does not validate SSL certificates; useful for self-signed certs (no trusted CA authority)
	 * @return SSLContext with validation disabled
	 */
	private static SSLContext getSSLContext() {
		TrustManager[] certs = new TrustManager[ ] {
			new X509TrustManager() {
				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				@Override
				public void checkClientTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
					// Skip cert check
				}
				@Override
				public void checkServerTrusted(final X509Certificate[] arg0, final String arg1) throws CertificateException {
					// Skip server trust check
				}
			}
		};
		SSLContext ctx = null;
		try {
			ctx = SSLContext.getInstance("TLS");
			ctx.init(null, certs, new SecureRandom());
		} catch (GeneralSecurityException ex) {
			LOG.error("Security Exception: " + ex.getMessage() + " - Proceeding anyway.", ex);
		}

		return ctx;
	}

	/**
	 * Provides a HostnameVerifier that ignores whether the hostname matches the SSL certificate; useful for self-signed certs.
	 * @return HostnameVerifier instance which does not verify that hostname matches SSL certificate.
	 */
	private static HostnameVerifier getHostnameVerifier() {
		return new HostnameVerifier() {
			@Override
			public boolean verify(final String hostname, final SSLSession session) {
				return true;
			}
		};
	}
}
