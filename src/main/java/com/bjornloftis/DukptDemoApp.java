package com.bjornloftis;

import com.bjornloftis.dukpt.DukptImpl;
import com.bjornloftis.dukpt.ipek.BaseDerivationKey;
import com.bjornloftis.dukpt.ipek.HexKeyComponent;
import com.bjornloftis.dukpt.ipek.InitialPinEncryptionKey;
import com.bjornloftis.genericterminal.GenericTerminalParser;
import com.bjornloftis.genericterminal.GenericTerminalSwipeDataGenerator;

import java.util.ArrayList;
import java.util.List;


public class DukptDemoApp
{

    public static final String KSN = "FFFF1000010000000007";

    public static void main( String[] args )
    {
        BaseDerivationKey bdk = createBaseDerivationKey();
        InitialPinEncryptionKey ipek = new InitialPinEncryptionKey(bdk, KSN);
        GenericTerminalSwipeDataGenerator terminalSwipeDataGenerator = new GenericTerminalSwipeDataGenerator(ipek);
        String swipe = terminalSwipeDataGenerator.generateSwipe();
        String dek = terminalSwipeDataGenerator.getDataEncryptionKey();
        System.out.println("Generated Swipe Data: " + swipe);
        System.out.println("Data Encryption Key: " + dek);
        GenericTerminalParser parser = new GenericTerminalParser(swipe);
        System.out.println("Encrypted Track Two Data: "+ parser.getTrackTwoEncrypted());
    }

    private static BaseDerivationKey createBaseDerivationKey() {
        List keyComponents = new ArrayList<HexKeyComponent>();
        keyComponents.add(new HexKeyComponent("B3D97485261218FCA6B7B6E1AE55CDB0", "EB0DAE"));
        keyComponents.add(new HexKeyComponent("E097DC6ECD542E5E0D550AA6310ACA23", "477BE4"));
        keyComponents.add(new HexKeyComponent("23E54BBA6E6ECB69C48EAAC4EFFAE508", "6F1E19"));
        return new BaseDerivationKey(keyComponents, "161C16");
    }


}
