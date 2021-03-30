package odev;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.exceptions.CryptoException;

public class Hw3CertificateFields {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private final ECertificate cert;

    public Hw3CertificateFields(ECertificate cert) {
        this.cert = cert;
    }

    public String getVersion() {
        return cert.getVersionStr();
    }

    public String getSerialNumber() {
        return String.valueOf(cert.getSerialNumber());
    }

    public String getSignatureAlgorithm() throws CryptoException {
        return SignatureAlg.fromAlgorithmIdentifier(cert.getSignatureAlgorithm()).first().getName();
    }

    public String getIssuer() {
        String res = "";
        res += "CN = " + cert.getIssuer().getCommonNameAttribute() + "\n";
        res += "OU = " + cert.getIssuer().getOrganizationalUnitNameAttribute() + "\n";
        res += "O = " + cert.getIssuer().getOrganizationNameAttribute() + "\n";
        res += "L = " + cert.getIssuer().getLocalityNameAttribute() + "\n";
        res += "C = " + cert.getIssuer().getCountryNameAttribute();
        return res;
    }

    public String getValidFrom() {
        return cert.getNotBefore().getTime().toLocaleString();
    }

    public String getValidTo() {
        return cert.getNotAfter().getTime().toLocaleString();
    }

    public String getSubject() {
        String res = "";
        res += "CN = " + cert.getSubject().getCommonNameAttribute() + "\n";
        res += "OU = " + cert.getSubject().getOrganizationalUnitNameAttribute() + "\n";
        res += "O = " + cert.getSubject().getOrganizationNameAttribute() + "\n";
        res += "L = " + cert.getSubject().getLocalityNameAttribute() + "\n";
        res += "S = " + cert.getSubject().getStateOrProvinceNameAttribute() + "\n";
        res += "C = " + cert.getSubject().getCountryNameAttribute();
        return res;
    }

    public String getPublicKeyAlgorithm() throws CryptoException {
        return SignatureAlg.fromAlgorithmIdentifier(cert.getPublicKeyAlgorithm()).first().getName();
    }

    public String getPublicKey() {
        return bytesToHex(cert.getSubjectPublicKeyInfo().getSubjectPublicKey());
    }


    public String getAuthorityKeyIdentifier() {
        return bytesToHex(cert.getExtensions().getAuthorityKeyIdentifier().getKeyIdentifier());
    }

    public String getSubjectKeyIdentifier() {
        return bytesToHex(cert.getExtensions().getSubjectKeyIdentifier().getValue());
    }

    public String getCertificatePolicies() {
        return cert.getExtensions().getCertificatePolicies().toString();
    }

    public String getBasicConstraints() {
        if (cert.getExtensions().getBasicConstraints() == null) {
            return null;
        }
        return cert.getExtensions().getBasicConstraints().toString();
    }

    public String getExtendedKeyUsage() {
        return cert.getExtensions().getExtendedKeyUsage().toString();
    }

    public String getCRLDistributionPoints() {
        return cert.getExtensions().getCRLDistributionPoints().toString();
    }

    public String getAuthorityInformationAccess() {
        return cert.getExtensions().getAuthorityInfoAccessSyntax().toString();
    }

    public String getSubjectAlternativeName() {
        return cert.getExtensions().getSubjectAltName().toString();
    }

    public String getKeyUsage() {
        return cert.getExtensions().getKeyUsage().toString();
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


}
