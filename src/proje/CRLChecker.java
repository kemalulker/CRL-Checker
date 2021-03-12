package proje;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECRL;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.asn.x509.EGeneralNames;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.crypto.util.SignUtil;
import tr.gov.tubitak.uekae.esya.asn.x509.ReasonFlags;
import utils.UtilsClass;

import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.List;

public class CRLChecker extends UtilsClass {
    private final String path = getRootDir() + "sertifikadeposu\\";
    private final ECRL crl;
    private final CertParser certParser;

    public CRLChecker(ECRL crl, CertParser certParser) {
        this.crl = crl;
        this.certParser = certParser;
    }

    public boolean verifyNextUpdate() {
        return crl.getNextUpdate().getTime().getTime() > System.currentTimeMillis();
    }

    public boolean verifyIssuer() {
        String certIssuer = certParser.getIssuer();
        return certIssuer.equals(getIssuer());
    }

    public boolean isIndirect() {
        return crl.isIndirectCRL();
    }

    public boolean verifyIDPSection() {
        if (!checkIDP()) {
            System.out.println("Warning IDP extension not exists.");
            return true;
        }
        return verifyIDPName() && verifyOnlyContains();
    }

    public ReasonFlags getReasons() {
        /*ReasonFlags certReasons = certParser.getReasons();
        if (checkIDP()) {
            ReasonFlags crlReasons = crl.getCRLExtensions().getIssuingDistributionPoint().getOnlySomeReasons();
            if (crlReasons != null && certReasons != null) {
                //return intersection
                return crlReasons;
            } else if (crlReasons != null) {
                return crlReasons;
            } else return certReasons;
        }
        return certReasons;*/
        return null;
    }

    public boolean verifyCRLPathAndSignature() throws IOException, ESYAException {
        ECertificate crlIssuerCert = certParser.getCRLIssuerCert();
        if (crlIssuerCert == null) {
            System.out.println("Issuer certificate not found.");
            return false;
        }
        if (!verifyKeyUsage(crlIssuerCert)) {
            System.out.println("Issuer certificate key usage not indicated CRL.");
            return false;
        }
        if (!verifyIssuerPath(crlIssuerCert)) {
            System.out.println("Path validation failed.");
            return false;
        }
        try {
            if (!verifyCRLSignature(crlIssuerCert)) {
                System.out.println("CRL signature validation failed.");
                return false;
            }
        } catch (CertificateException | CRLException e) {
            e.printStackTrace();
        }
        return true;
    }

    private boolean verifyCRLSignature(ECertificate crlIssuerCert) throws CertificateException, CRLException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate issuerCert = crlIssuerCert.asX509Certificate();
        byte[] crlBytes = crl.getEncoded();
        InputStream in = new ByteArrayInputStream(crlBytes);
        X509CRL crlCert = (X509CRL) certFactory.generateCRL(in);
        try {
            crlCert.verify(issuerCert.getPublicKey());
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }
        return true;
    }

    private boolean verifyIssuerPath(ECertificate currCert) throws IOException, ESYAException {
        if (!currCert.getSubject().getCommonNameAttribute().equals(currCert.getIssuer().getCommonNameAttribute())) {
            ECertificate upCert;
            do {
                upCert = certParser.getIssuerCert(currCert);
                if (upCert == null) {
                    System.out.println("Warning: Issuer http not found in path. " + currCert.getSubject().getCommonNameAttribute());
                    return true;
                }
                X509Certificate upCertificate = upCert.asX509Certificate();
                X509Certificate currCertificate = currCert.asX509Certificate();
                try {
                    currCertificate.verify(upCertificate.getPublicKey());
                } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException
                        | SignatureException e) {
                    return false;
                }
                currCert = upCert;
            }
            while (!upCert.getSubject().getCommonNameAttribute().equals(upCert.getIssuer().getCommonNameAttribute()));
            return verifyRootCert(upCert.getSubject().getCommonNameAttribute());
        }
        return verifyRootCert(currCert.getSubject().getCommonNameAttribute());
    }

    private boolean verifyRootCert(String rootCertName) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(
                    path + "rootCerts.txt"));
            String line = reader.readLine();
            while (line != null) {
                if (line.contains(rootCertName)) return true;
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean verifyKeyUsage(ECertificate cert) {
        return cert.getExtensions().getKeyUsage().isCRLSign();
    }

    private boolean verifyIDPName() {
        boolean idpNameEqDpName = false;
        EGeneralNames idpNames = getIDPNames();
        if (idpNames != null && idpNames.getElementCount() > 0) {
            List<String> dpNames = certParser.getCRLHttpAddresses();
            for (int i = 0; i < idpNames.getElementCount(); i++) {
                for (String dpName : dpNames) {
                    if (idpNames.getElement(i).toString().equals(dpName)) {
                        idpNameEqDpName = true;
                        break;
                    }
                }
            }
        } else {
            System.out.println("Warning IDP names not exists.");
            return true;
        }

        return idpNameEqDpName;
    }

    private boolean verifyOnlyContains() {
        if (crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsUserCerts()) {
            return !crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsCACerts() &&
                    !crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsAttributeCerts();
        } else if (crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsCACerts()) {
            return !crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsUserCerts() &&
                    !crl.getCRLExtensions().getIssuingDistributionPoint().isOnlyContainsAttributeCerts();
        } else {
            return false;
        }
    }

    private boolean checkIDP() {
        return crl.getCRLExtensions().getIssuingDistributionPoint() != null;
    }

    private EGeneralNames getIDPNames() {
        return crl.getCRLExtensions().getIssuingDistributionPoint().getDistributionPoint().getFullName();
    }

    private String getIssuer() {
        return crl.getIssuer().getCommonNameAttribute();
    }


}
