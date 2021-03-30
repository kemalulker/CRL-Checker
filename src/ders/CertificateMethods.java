package ders;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;

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

}
