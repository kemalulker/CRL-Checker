package proje;

import tr.gov.tubitak.uekae.esya.api.asn.x509.ECRL;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ECertificate;
import tr.gov.tubitak.uekae.esya.api.asn.x509.ERevokedCertificateElement;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.asn.util.AsnIO;
import tr.gov.tubitak.uekae.esya.asn.x509.ReasonFlags;
import utils.UtilsClass;

import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

public class RevocationChecker extends UtilsClass {
    private final String path = getRootDir() + "sertifikadeposu\\";
    private final CertParser certParser;
    private final List<Reason> reasons = new ArrayList<>();
    private Reason certStatus = Reason.unrevoked;

    public RevocationChecker(ECertificate cert) throws CertificateException {
        certParser = new CertParser(cert);
    }

    public void verifyRevocation() throws IOException, ESYAException {
        String crlName = saveValidCRLCert();
        if (crlName == null) {
            System.out.println("CRL not found.");
            System.exit(0);
        }
        System.out.println("CRL saved as " + crlName);
        byte[] byteCRL =
                new AsnIO().dosyadanOKU(path + crlName + ".crl");
        ECRL crl = new ECRL(byteCRL);
        String serialNumber = certParser.getSerialNumber();
        for (int i = 0; i < crl.getRevokedCerticateElementCount(); i++) {
            ERevokedCertificateElement revokedCertificateElement = crl.getRevokedCerticateElement(i);
            String revokedSerialNumber = revokedCertificateElement.getUserCertificate().toString();
            if (revokedSerialNumber.equals(serialNumber)) {
                int reasonNum = revokedCertificateElement.getCRLReason();
                String revocationDate = revokedCertificateElement.getRevocationDate().toLocaleString();
                certStatus = reasons.get(reasonNum);
                System.out.println(certParser.getCertificateName());
                System.out.println("Revoked at: " + revocationDate);
                System.out.println("Revocation reason: " + certStatus);
                return;
            }
        }
        System.out.println(certParser.getCertificateName() + " NOT REVOKED.");
    }

    private String saveValidCRLCert() throws IOException, ESYAException {
        List<String> httpCRLAddresses = certParser.getCRLHttpAddresses();
        if (httpCRLAddresses == null) {
            System.out.println("CRL http addresses not exists");
            System.exit(0);
        }
        if (!(httpCRLAddresses.size() > 0)) return null;
        CRLChecker crlChecker;
        String crlName = null;
        for (String httpAddress : httpCRLAddresses) {
            URL url = new URL(httpAddress);
            URLConnection connection = url.openConnection();
            try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
                ECRL crl = new ECRL(inStream);
                crlChecker = new CRLChecker(crl, certParser);

                if (!crlChecker.verifyNextUpdate()) {
                    System.out.println("Next update is past.");
                    continue;
                }

                if (crlChecker.isIndirect()) {
                    System.out.println("Warning: Indirect CRL.");
                    continue;
                }

                if (!crlChecker.verifyIssuer()) {
                    System.out.println("Issuer match check failed.");
                    continue;
                }

                if (!crlChecker.verifyIDPSection()) {
                    System.out.println("IDP name does not match.");
                    continue;
                }

                ReasonFlags interim_reasons_mask = crlChecker.getReasons();
                if (interim_reasons_mask == null) {
                    setAllReasons();
                    System.out.println("Warning setting all-reasons.");
                }

                if (!crlChecker.verifyCRLPathAndSignature()) {
                    continue;
                }

                crlName = crl.getIssuer().getCommonNameAttribute() + " CRL";
                saveCRLtoFile(crlName, crl);
                break;
            }
        }
        return crlName;
    }

    private void saveCRLtoFile(String name, ECRL crl) throws IOException {
        FileOutputStream os = new FileOutputStream(path + name + ".crl");
        os.write(crl.getEncoded());
        os.close();
    }

    private void setAllReasons() {
        reasons.add(Reason.unspecified);
        reasons.add(Reason.keyCompromise);
        reasons.add(Reason.cACompromise);
        reasons.add(Reason.affiliationChanged);
        reasons.add(Reason.superseded);
        reasons.add(Reason.cessationOfOperation);
        reasons.add(Reason.certificateHold);
        reasons.add(Reason.privilegeWithdrawn);
        reasons.add(Reason.aACompromise);
    }

    private enum Reason {
        unspecified,
        keyCompromise,
        cACompromise,
        affiliationChanged,
        superseded,
        cessationOfOperation,
        certificateHold,
        privilegeWithdrawn,
        aACompromise,
        unrevoked
    }


}
