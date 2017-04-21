package com.qiwi.sslpin;

import android.content.Context;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public class SSLPinner {

    private final long TIMEOUT = 30; // seconds

    //@Inject
    public SSLPinner() {

    }

    public OkHttpClient.Builder getSSLPinnedClientBuilder(Context context, int rawRes,
            String endpoint) {
        return getSSLPinnedClientBuilder(buildCertificateFromRawResource(context, rawRes),
                endpoint);
    }

    public OkHttpClient.Builder getSSLPinnedClientBuilder(Certificate certificate,
            String endpoint) {
        try {
            return buildSSLClient(endpoint, certificate);
        } catch (Throwable t) {
            trace(t);
            return null;
        }
    }

    private OkHttpClient.Builder getDefaultClientBuilder() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.readTimeout(TIMEOUT, TimeUnit.SECONDS).connectTimeout(TIMEOUT, TimeUnit.SECONDS);
        return builder;
    }


    private Certificate buildCertificateFromRawResource(Context context,
            int certificateRawResource) {
        try {
            InputStream is = new BufferedInputStream(
                    context.getResources().openRawResource(certificateRawResource));
            try {
                return CertificateFactory.getInstance("X.509").generateCertificate(is);
            } finally {
                is.close();
            }
        } catch (Exception e) {
            trace(e);
        }
        return null;
    }

    private OkHttpClient.Builder buildSSLClient(String endpoint, Certificate... certificates)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException,
            KeyManagementException {
        OkHttpClient.Builder builder = getDefaultClientBuilder();
        TrustManagerFactory trustedManagerFactory = getTrustedManagerFactory(certificates);
        builder.sslSocketFactory(getSSLSocketFactory(trustedManagerFactory),
                (X509TrustManager) trustedManagerFactory.getTrustManagers()[0]);
        if (endpoint != null && certificates != null) {
            for (Certificate cert : certificates) {
                if (cert != null) {
                    builder.certificatePinner(new CertificatePinner.Builder()
                            .add(endpoint, CertificatePinner.pin(cert)).build());
                }
            }
        }
        return builder;
    }

    private TrustManagerFactory getTrustedManagerFactory(Certificate... certificates)
            throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(getKeystore(certificates));
        return tmf;
    }

    private KeyStore getKeystore(Certificate... certificates)
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        String keyStoreType = KeyStore.getDefaultType();
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        if (certificates != null) {
            for (int i = 0; i < certificates.length; i++) {
                Certificate cert = certificates[i];
                if (cert != null) {
                    keyStore.setCertificateEntry(String.valueOf(i), cert);
                }
            }
        }
        return keyStore;
    }

    private SSLSocketFactory getSSLSocketFactory(TrustManagerFactory trustManagerFactory)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslcontext = SSLContext.getInstance("TLS");
        sslcontext.init(null, trustManagerFactory.getTrustManagers(), null);
        return sslcontext.getSocketFactory();
    }

    private void trace(Throwable throwable) {
        if (BuildConfig.DEBUG) {
            throwable.printStackTrace();
        }
    }

}
