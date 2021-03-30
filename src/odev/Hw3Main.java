package odev;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.crypto.exceptions.CryptoException;
import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;

import java.io.IOException;
import java.util.Locale;

public class Hw3Main extends UtilsClass {

    private static final String certPath = getRootDir() + "sertifikadeposu\\tubitak.cer";

    public static void main(String[] args) throws IOException, ESYAException {

        byte[] byteCert =
                new AsnIO().dosyadanOKU(certPath);
        ECertificate cert = new ECertificate(byteCert);
        printCertificateFields(cert); //Soru 1
        newLine();
        printCertificatePath(cert); //Soru 2
        newLine();
        verifySignature(cert); //Soru 3
        newLine();
        testPfxSigner(); //Soru 4 Bonus
    }

    private static void printCertificateFields(ECertificate cert) throws CryptoException {
        Hw3CertificateFields parser = new Hw3CertificateFields(cert);
        String version = parser.getVersion();
        String serialNumber = parser.getSerialNumber();
        String signatureAlgorithm = parser.getSignatureAlgorithm();
        String issuer = parser.getIssuer();
        String validFrom = parser.getValidFrom();
        String validTo = parser.getValidTo();
        String subject = parser.getSubject();
        String publicKeyAlgorithm = parser.getPublicKeyAlgorithm();
        String publicKey = parser.getPublicKey();
        String authorityKeyIdentifier = parser.getAuthorityKeyIdentifier();
        String subjectKeyIdentifier = parser.getSubjectKeyIdentifier();
        String certificatePolicies = parser.getCertificatePolicies();
        String basicConstraints = parser.getBasicConstraints();
        String extendedKeyUsage = parser.getExtendedKeyUsage();
        String crlDistributionPoints = parser.getCRLDistributionPoints();
        String authorityInformationAccess = parser.getAuthorityInformationAccess();
        String subjectAlternativeName = parser.getSubjectAlternativeName();
        String keyUsage = parser.getKeyUsage();

        System.out.println("Version: " + version);
        System.out.println("Serial Number: " + serialNumber);
        System.out.println("Signature Algorithm: " + signatureAlgorithm);
        System.out.println("Issuer:\n" + issuer);
        System.out.println("Valid From: " + validFrom);
        System.out.println("Valid To: " + validTo);
        System.out.println("Subject:\n" + subject);
        System.out.println("Public Key Algorithm: " + publicKeyAlgorithm);
        System.out.println("Public Key:");
        printHexFormatted(publicKey);
        newLine();
        System.out.println("Authority Key Identifier:\n" + authorityKeyIdentifier.toLowerCase(Locale.ROOT));
        System.out.println("Subject Key Identifier:\n" + subjectKeyIdentifier.toLowerCase(Locale.ROOT));
        System.out.println("Certificate Policies:\n" + certificatePolicies);
        System.out.println("Basic Constraints:\n" + basicConstraints);
        System.out.println("Extended Key Usage:\n" + extendedKeyUsage);
        System.out.println("CRL Distribution Points:\n" + crlDistributionPoints);
        System.out.println("Authority Information Access:\n" + authorityInformationAccess);
        System.out.println("Subject Alternative Name:\n" + subjectAlternativeName);
        System.out.println("Key Usage:\n" + keyUsage);
    }

    private static void printCertificatePath(ECertificate cert) {
        System.out.println("Certificate Path:");
        Hw3PathFinder finder = new Hw3PathFinder(cert);
        try {
            finder.findPathToRoot();
        } catch (IOException | ESYAException e) {
            e.printStackTrace();
        }
    }

    private static void verifySignature(ECertificate cert) {
        Hw3SignUtil signUtil = new Hw3SignUtil(cert);
        try {
            String res = signUtil.verifySign() ? "Signature verified." : "Signature could not verified.";
            System.out.println(res);
        } catch (IOException | ESYAException e) {
            e.printStackTrace();
        }
    }

    private static void testPfxSigner() {
        Hw3PfxSigner pfxSigner = new Hw3PfxSigner();
        try {
            pfxSigner.testBESSign();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printHexFormatted(String hex) {
        hex = hex.toLowerCase(Locale.ROOT);
        for (int i = 0; i < hex.length(); i++) {
            if (i % 60 == 0 && i != 0) System.out.println();
            if (i % 2 == 0 && i % 60 != 0) System.out.print(" ");
            System.out.print(hex.charAt(i));
        }
    }

    private static void newLine() {
        System.out.println();
    }
}
