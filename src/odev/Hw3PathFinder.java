package odev;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;

public class Hw3PathFinder {
    private final ECertificate cert;

    public Hw3PathFinder(ECertificate cert) {
        this.cert = cert;
    }

    public void findPathToRoot() throws IOException, ESYAException {
        ECertificate tmpCert = cert;
        while (!tmpCert.isSelfIssued()) {
            System.out.println(tmpCert.getSubject().getCommonNameAttribute()); //end and sub root certificates.
            tmpCert = getIssuerCert(tmpCert);
            if (tmpCert == null) return;
        }
        System.out.println(tmpCert.getSubject().getCommonNameAttribute()); //root certificate.
    }

    private ECertificate getIssuerCert(ECertificate tmpCert) throws IOException, ESYAException {
        List<String> issuerHTTPAddresses = tmpCert.getExtensions().getAuthorityInfoAccessSyntax().getCAIssuerAddresses();
        if (issuerHTTPAddresses != null && issuerHTTPAddresses.size() > 0) {
            for (String httpAddress : issuerHTTPAddresses) {
                URL url = new URL(httpAddress);
                URLConnection connection = url.openConnection();
                try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
                    return new ECertificate(inStream);
                }
            }
        }
        System.out.println("For " + tmpCert.getSubject().getCommonNameAttribute() +
                " Authority Information Access extension not found!");
        return null;
    }

}
