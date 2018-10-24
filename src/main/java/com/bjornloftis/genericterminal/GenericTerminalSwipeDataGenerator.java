package com.bjornloftis.genericterminal;

import com.bjornloftis.dukpt.ipek.InitialPinEncryptionKey;
import com.bjornloftis.dukpt.DukptImpl;
import org.bouncycastle.util.encoders.Hex;

public class GenericTerminalSwipeDataGenerator {

    private DukptImpl dukpt;
    private InitialPinEncryptionKey ipek;

    public GenericTerminalSwipeDataGenerator(InitialPinEncryptionKey ipek){
        this.ipek = ipek;
        this.dukpt = new DukptImpl(ipek);
    }

    private static final int IPEK_KEY_LENGTH = 128 / 8;

    public String getDataEncryptionKey() {
        return dukpt.getDataEncryptionKey();
    }

    public String generateSwipe() {
        DukptImpl dukpt = new DukptImpl(ipek);
        String swipe = null;
        try {
            String ksn = ipek.getKsn();
            byte[] ksnbytes = Hex.decode(ksn);

            // Create our plaintext track1 and track2 as well as masked track1 and track2
            String track1 = "%B4012002000060016^VI TEST CREDIT^251210118039000000000396?";
            String track2 = ";4012002000060016=25121011803939600000?";
            String maskedtrack1 = "%B4012********0016^VI TEST CREDIT^251210118039000000000396?";
            String maskedtrack2 = ";4012********0016=25121011803939600000?";
            byte[] track1bytes = track1.getBytes();
            byte[] track2bytes = track2.getBytes();


            String trackOneCipherText = dukpt.encryptTrackDataTDEAZeroBytePadding(track1bytes);
            String trackTwoCipherText = dukpt.encryptTrackDataTDEAZeroBytePadding(track2bytes);

            swipe = maskedtrack1 + "|" + maskedtrack2 + "|" + "53124092" + "|" + trackOneCipherText.toUpperCase() + "|" + trackTwoCipherText.toUpperCase() + "||" + ksn + "||";

        } catch (Exception ex) {
            System.out.println("\nSwipe Generation Failed: \n");
            ex.printStackTrace();
        }
        return swipe;
    }
}
