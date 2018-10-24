package com.bjornloftis.dukpt.ipek;

import java.math.BigInteger;

class BinaryKeyComponent {

    private final String hexValue;
    private final String binaryValue;

    BinaryKeyComponent(String hexValue) {
        this.hexValue = hexValue;
        this.binaryValue = pad(new BigInteger(hexValue, 16).toString(2));
    }

    String getBinaryValue() {
        return binaryValue;
    }

    String getHexValue() {
        return hexValue;
    }

    private String separateBinaryValues(String binaryValue) {
        StringBuffer result = new StringBuffer();
        for (int i = 0; i < binaryValue.length(); i++) {
            result.append(binaryValue.substring(i, i + 1));
            if ((i + 1) % 4 == 0 && i != binaryValue.length() - 1) {
                result.append(" ");
            }
        }
        return result.toString();
    }

    private String pad(String value) {
        return String.format("%128s", value).replace(" ", "0");
    }

    public String toString() {
        return "HEX: " + hexValue + "\nBINARY: " + separateBinaryValues(binaryValue);
    }

}
