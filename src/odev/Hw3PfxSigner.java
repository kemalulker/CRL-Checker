package odev;

import org.junit.Test;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.PolicyReader;
import tr.gov.tubitak.uekae.esya.api.certificate.validation.policy.ValidationPolicy;
import tr.gov.tubitak.uekae.esya.api.cmssignature.ISignable;
import tr.gov.tubitak.uekae.esya.api.cmssignature.SignableByteArray;
import tr.gov.tubitak.uekae.esya.api.cmssignature.attribute.EParameters;
import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.BaseSignedData;
import tr.gov.tubitak.uekae.esya.api.cmssignature.signature.ESignatureType;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedDataValidationResult;
import tr.gov.tubitak.uekae.esya.api.cmssignature.validation.SignedData_Status;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.common.ESYARuntimeException;
import tr.gov.tubitak.uekae.esya.api.common.crypto.BaseSigner;
import tr.gov.tubitak.uekae.esya.api.common.util.bag.Pair;
import tr.gov.tubitak.uekae.esya.api.crypto.Crypto;
import tr.gov.tubitak.uekae.esya.api.crypto.Signer;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.SignatureAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.util.PfxParser;
import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;

import static junit.framework.TestCase.assertEquals;

public class Hw3PfxSigner extends UtilsClass {

    private static final String FilePath = getRootDir() + "\\sertifikadeposu\\QCA1_1.p12";
    private static final String PFX_PIN = "123456";
    private static final String policyFile = getRootDir() + "\\config\\certval-policy.xml";
    private static ValidationPolicy validationPolicy = null;

    @Test
    public void testBESSign() throws Exception {
        BaseSignedData baseSignedData = new BaseSignedData();
        String signedData = "Kemal ULKER";
        ISignable content = new SignableByteArray(signedData.getBytes());
        baseSignedData.addContent(content);

        HashMap<String, Object> params = new HashMap<String, Object>();

        //if the user does not want certificate validation at generating signature,he can add
        //P_VALIDATE_CERTIFICATE_BEFORE_SIGNING parameter with its value set to false
        //params.put(EParameters.P_VALIDATE_CERTIFICATE_BEFORE_SIGNING, false);

        //necessary for certificate validation.By default,certificate validation is done
        params.put(EParameters.P_CERT_VALIDATION_POLICY, getPolicy());

        ECertificate cert = getCertificateFromPFX();
        BaseSigner signer = getSignerFromPFX();

        baseSignedData.addSigner(ESignatureType.TYPE_BES, cert, signer, null, params);
        byte[] signedDocument = baseSignedData.getEncoded();

        //write the contentinfo to file
        AsnIO.dosyayaz(signedDocument, getRootDir() + "\\sertifikadeposu\\" + "kemalPfxImza.p7s");

        CadesSignatureValidation signatureValidation = new CadesSignatureValidation();
        SignedDataValidationResult validationResult = signatureValidation.validate(signedDocument, null);
        System.out.println(validationResult);

        assertEquals(SignedData_Status.ALL_VALID, validationResult.getSDStatus());
    }

    public ECertificate getCertificateFromPFX() throws Exception {
        //Pfx okunuyor.
        FileInputStream fis = new FileInputStream(FilePath);
        PfxParser pfxParser = new PfxParser(fis, PFX_PIN.toCharArray());
        List<Pair<ECertificate, PrivateKey>> entries = pfxParser.getCertificatesAndKeys();
        return entries.get(0).getObject1();
    }

    public Signer getSignerFromPFX() throws Exception {
        //Pfx okunuyor.
        FileInputStream fis = new FileInputStream(FilePath);
        PfxParser pfxParser = new PfxParser(fis, PFX_PIN.toCharArray());
        List<Pair<ECertificate, PrivateKey>> entries = pfxParser.getCertificatesAndKeys();

        Signer signer = Crypto.getSigner(SignatureAlg.RSA_SHA256);
        signer.init(entries.get(0).getObject2());
        return signer;
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
