package proje;


import tr.gov.tubitak.uekae.esya.api.asn.x509.ECRLDistributionPoints;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.asn.x509.EName;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.asn.x509.ReasonFlags;
import utils.UtilsClass;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.util.List;

public class CertParser extends UtilsClass {
    private final ECertificate cert;

    public CertParser(ECertificate cert) throws CertificateException {
        this.cert = cert;
    }

    public String getCertificateName() {
        return cert.getSubject().getCommonNameAttribute();
    }

    public List<String> getCRLHttpAddresses() {
        if (cert.getExtensions().getCRLDistributionPoints() == null) return null;
        List<String> httpCRLAddresses;
        ECRLDistributionPoints ecrlDistributionPoints = cert.getExtensions().getCRLDistributionPoints();
        httpCRLAddresses = ecrlDistributionPoints.getHttpAddresses();
        return httpCRLAddresses;
    }

    public String getIssuer() {
        return cert.getIssuer().getCommonNameAttribute();
    }

    public boolean checkBasicConstraints() {
        return cert.getExtensions().getBasicConstraints().isCA();
    }

    public ReasonFlags getReasons() {
        return cert.getExtensions().getCRLDistributionPoints().getCRLDistributionPoint(0).getObject().reasons;
    }

    public ECertificate getCRLIssuerCert() throws IOException, ESYAException {
        return getCertificate(cert);
    }

    public ECertificate getIssuerCert(ECertificate issuerCert) throws IOException, ESYAException {
        return getCertificate(issuerCert);
    }

    public String getSerialNumber() {
        return cert.getSerialNumber().toString();
    }

    private ECertificate getCertificate(ECertificate issuerCert) throws IOException, ESYAException {
        if (issuerCert.isSelfIssued()) {
            return issuerCert;
        }
        List<String> issuerHTTPAddresses = issuerCert.getExtensions().getAuthorityInfoAccessSyntax().getCAIssuerAddresses();
        if (issuerHTTPAddresses.size() > 0) {
            for (String httpAddress : issuerHTTPAddresses) {
                URL url = new URL(httpAddress);
                URLConnection connection = url.openConnection();
                try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
                    return new ECertificate(inStream);
                }
            }
        }
        return null;
    }


}
