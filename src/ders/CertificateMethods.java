package ders;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECRLDistributionPoint;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECRLDistributionPoints;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.save.CertStoreCRLSaver;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;


public class CertificateMethods {
    private final ECertificate cert;

    public CertificateMethods(ECertificate cert) {
        this.cert = cert;
    }

    public String getCertificateCommonName() {
        return cert.getSubject().getCommonNameAttribute();
    }

    public String getOrganizationName() {
        return cert.getSubject().getOrganizationNameAttribute();
    }

    public String getLocalityName() {
        return cert.getSubject().getLocalityNameAttribute();
    }

    public String getValidFrom() {
        return cert.getNotBefore().getTime().toLocaleString();
    }

    public String getValidTo() {
        return cert.getNotAfter().getTime().toLocaleString();
    }

    public String getCRLHttpAddress() {
        List<String> httpCRLAddress;
        ECRLDistributionPoints ecrlDistributionPoints = cert.getExtensions().getCRLDistributionPoints();
        httpCRLAddress = ecrlDistributionPoints.getHttpAddresses();
        String retValue = (httpCRLAddress.size() > 0) ? httpCRLAddress.get(0): "CRL adresi yok!";
        return retValue;
    }

    private void saveCRLCert() throws IOException, CertificateException, CRLException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509CRL crl = null;
        String httpAddress = getCRLHttpAddress();
        URL url = new URL(httpAddress);
        URLConnection connection = url.openConnection();
        try(DataInputStream inStream = new DataInputStream(connection.getInputStream())){
            crl = (X509CRL)cf.generateCRL(inStream);
        }
    }
}
