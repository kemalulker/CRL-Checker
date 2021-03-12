package utils;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.CertificateValidation;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.ValidationSystem;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.check.certificate.CertificateStatusInfo;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.PolicyReader;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.ValidationPolicy;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;

import java.util.Calendar;

public class CertValidation extends UtilsClass {
    private final ECertificate cert;
    private ValidationPolicy policy;

    public CertValidation(ECertificate cert) throws ESYAException {
        this.cert = cert;
        policy = new ValidationPolicy();
        String policyPath = getRootDir() + "config\\certval-policy.xml";
        policy = PolicyReader.readValidationPolicy(policyPath);
    }

    public void validate() throws ESYAException {
        ValidationSystem vs = CertificateValidation.createValidationSystem(policy);
        vs.setBaseValidationTime(Calendar.getInstance());
        CertificateStatusInfo csi = CertificateValidation.validateCertificate(vs, cert);
        System.out.println(csi.toString());
    }
}
