package ders;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;
import utils.UtilsClass;
import java.io.IOException;


public class CertificateParser extends UtilsClass {

    private static final String certPath = getRootDir() + "sertifikadeposu\\tubitak.cer";

    public static void main(String[] args) throws IOException, ESYAException {

        byte[] byteCert =
                new AsnIO().dosyadanOKU(certPath);
        ECertificate cert = new ECertificate(byteCert);
        CertificateMethods parser = new CertificateMethods(cert);
        String cN = parser.getCertificateCommonName();
        String oN = parser.getOrganizationName();
        String lN = parser.getLocalityName();
        String validFrom = parser.getValidFrom();
        String validTo = parser.getValidTo();
        System.out.println("CN: " + cN);
        System.out.println("ON: " + oN);
        System.out.println("LN: " + lN);
        System.out.println("Valid From: " + validFrom);
        System.out.println("Valid To: " + validTo);

    }
}
