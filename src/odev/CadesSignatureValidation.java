package odev;

import tr.gov.tubitak.uekae.esya.api.asn.profile.TurkishESigProfile;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.PolicyReader;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.ValidationPolicy;
import tr.gov.tubitak.uekae.esya.api.cmssignature.ISignable;
import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.EParameters;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedDataValidation;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedDataValidationResult;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.common.ESYARuntimeException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Hashtable;

public class CadesSignatureValidation extends UtilsClass {

    private static final String policyFile = getRootDir() + "\\config\\certval-policy.xml";
    private static ValidationPolicy validationPolicy = null;

    public SignedDataValidationResult validate(byte[] signature, ISignable externalContent) throws Exception {
        return validate(signature, externalContent, getPolicy(), null);
    }

    public SignedDataValidationResult validate(byte[] signature, ISignable externalContent, TurkishESigProfile turkishESigProfile) throws Exception {
        return validate(signature, externalContent, getPolicy(), turkishESigProfile);
    }

    public SignedDataValidationResult validate(byte[] signature, ISignable externalContent, ValidationPolicy policy, TurkishESigProfile turkishESigProfile) throws Exception {
        Hashtable<String, Object> params = new Hashtable<String, Object>();

        if (turkishESigProfile != null)
            params.put(EParameters.P_VALIDATION_PROFILE, turkishESigProfile);

        params.put(EParameters.P_CERT_VALIDATION_POLICY, policy);

        if (externalContent != null)
            params.put(EParameters.P_EXTERNAL_CONTENT, externalContent);

        //Use only reference and their corresponding value to validate signature
        params.put(EParameters.P_FORCE_STRICT_REFERENCE_USE, true);

        //Ignore grace period which means allow usage of CRL published before signature time
        //params.put(EParameters.P_IGNORE_GRACE, true);

        //Use multiple policies if you want to use different policies to validate different types of certificate
        //CertValidationPolicies certificateValidationPolicies = new CertValidationPolicies();
        //certificateValidationPolicies.register(CertificateType.DEFAULT.toString(), policy);
        //ValidationPolicy maliMuhurPolicy=PolicyReader.readValidationPolicy(new FileInputStream("./config/certval-policy-malimuhur.xml"));
        //certificateValidationPolicies.register(CertificateType.MaliMuhurCertificate.toString(), maliMuhurPolicy);
        //params.put(EParameters.P_CERT_VALIDATION_POLICIES, certificateValidationPolicies);

        SignedDataValidation sdv = new SignedDataValidation();
        SignedDataValidationResult validationResult = sdv.verify(signature, params);

        return validationResult;
    }

    private synchronized ValidationPolicy getPolicy() throws ESYAException {

        if (validationPolicy == null) {
            try {
                validationPolicy = PolicyReader.readValidationPolicy(new FileInputStream(policyFile));
            } catch (FileNotFoundException e) {
                throw new ESYARuntimeException("Policy file could not be found", e);
            }
        }
        return validationPolicy;
    }
}
