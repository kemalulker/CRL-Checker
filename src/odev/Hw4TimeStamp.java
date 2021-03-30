package odev;

import tr.gov.tubitak.uekae.esya.api.asn.cms.EContentInfo;
import tr.gov.tubitak.uekae.esya.api.asn.cms.ESignedData;
import tr.gov.tubitak.uekae.esya.api.asn.pkixtsp.ETSTInfo;
import tr.gov.tubitak.uekae.esya.api.asn.pkixtsp.ETimeStampResponse;
import tr.gov.tubitak.uekae.esya.api.common.ESYAException;
import tr.gov.tubitak.uekae.esya.api.crypto.alg.DigestAlg;
import tr.gov.tubitak.uekae.esya.api.crypto.exceptions.CryptoException;
import tr.gov.tubitak.uekae.esya.api.crypto.util.DigestUtil;
import tr.gov.tubitak.uekae.esya.api.infra.tsclient.TSClient;
import tr.gov.tubitak.uekae.esya.api.infra.tsclient.TSSettings;

public class Hw4TimeStamp {


    public void printTimeStamp() throws ESYAException {
        ETimeStampResponse timeStampResp = getTimeStamp();
        EContentInfo contentInfo = timeStampResp.getContentInfo();
        ESignedData signedData = new ESignedData(contentInfo.getContent());
        ETSTInfo tstInfo = new ETSTInfo(signedData.getEncapsulatedContentInfo().getContent());
        String messageImprint = tstInfo.getObject().messageImprint.hashedMessage.toString();
        String serialNumber = tstInfo.getObject().serialNumber.value.toString();
        String genTime = tstInfo.getObject().genTime.getTime().getTime().toLocaleString();
        String nonce = tstInfo.getObject().nonce.value.toString();
        //Null check required because TSA name is optional.
        String tsaField = tstInfo.getObject().tsa == null ? "not exists" : tstInfo.getObject().tsa.toString();

        System.out.println("Message Imprint:\n" + messageImprint);
        System.out.println("Serial Number:\n" + serialNumber);
        System.out.println("Generate Time:\n" + genTime);
        System.out.println("Nonce:\n" + nonce);
        System.out.println("TSA Name Field:\n" + tsaField);
    }

    private ETimeStampResponse getTimeStamp() throws ESYAException {
        TSClient tsClient = new TSClient();
        String tsServer = "http://zdsa1.test2.kamusm.gov.tr/";
        int userId = 1;
        String userPassword = "12345678";
        TSSettings tsSettings = new TSSettings(tsServer, userId, userPassword);
        byte[] digest = getDigest();
        return tsClient.timestamp(digest, tsSettings);
    }

    private byte[] getDigest() throws CryptoException {
        String data = "Kemal ULKER";
        return DigestUtil.digest(DigestAlg.SHA256, data.getBytes());
    }

}
