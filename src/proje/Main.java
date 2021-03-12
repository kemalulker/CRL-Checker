package proje;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;
import utils.UtilsClass;

import java.io.IOException;
import java.security.cert.CertificateException;


public class Main extends UtilsClass {

    private static final String certPath = getRootDir() + "sertifikadeposu\\ssl.cer";

    public static void main(String[] args) throws IOException, ESYAException, CertificateException {

        byte[] byteCert =
                new AsnIO().dosyadanOKU(certPath);
        ECertificate cert = new ECertificate(byteCert);
        RevocationChecker revocationChecker = new RevocationChecker(cert);
        revocationChecker.verifyRevocation();

    }
}
