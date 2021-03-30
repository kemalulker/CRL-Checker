package odev;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.util.SignUtil;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

public class Hw3SignUtil {

    private final ECertificate cert;

    public Hw3SignUtil(ECertificate cert) {
        this.cert = cert;
    }

    public boolean verifySign() throws IOException, ESYAException {
        ECertificate issuerCert = getIssuerCertificate(cert);
        if (issuerCert == null) {
            System.out.println("Issuer certificate not found.");
            return false;
        }
        if (issuerCert == cert) {
            System.out.println("Root certificate must verified by Trusted Store.");
            return false;
        }
        SignatureAlg signatureAlg = SignatureAlg.fromAlgorithmIdentifier(issuerCert.getSignatureAlgorithm()).first();
        byte[] signature = cert.getSignatureValue();
        byte[] tbsCertificate = cert.getTBSEncodedBytes();
        return SignUtil.verify(signatureAlg, tbsCertificate, signature, issuerCert);
    }

    private ECertificate getIssuerCertificate(ECertificate cert) throws IOException, ESYAException {
        if (cert.isSelfIssued()) {
            return cert;
        }
        List<String> issuerHTTPAddresses = cert.getExtensions().getAuthorityInfoAccessSyntax().getCAIssuerAddresses();
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
