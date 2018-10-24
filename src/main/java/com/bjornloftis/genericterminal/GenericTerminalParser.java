package com.bjornloftis.genericterminal;


import org.apache.commons.lang3.StringUtils;

public class GenericTerminalParser {

    private static final int TRACK_ONE_MASKED_POSITION = 0;
    private static final int TRACK_TWO_MASKED_POSITION = 1;
    private static final int DEVICE_SERIAL_NUMBER = 2;
    private static final int TRACK_ONE_ENCRYPTED_POSITION = 3;
    private static final int TRACK_TWO_ENCRYPTED_POSITION = 4;
    private static final int TRACK_THREE_ENCRYPTED_POSITION = 5;
    private static final int KSN_POSITION = 6;
    private static final int CRYPTOGRAPHIC_ALGORITHM_POSITION = 7;
    private static final int METADATA_POSITION = 8;

    private final String trackOneMasked;

    private final String trackTwoMasked;
    private final String deviceSerialNumber;
    private final String trackOneEncrypted;
    private final String trackTwoEncrypted;
    private final String trackThreeEncrypted;
    private final String ksn;
    private final String cryptographicAlgorithm;
    private final String metadata;

    public GenericTerminalParser(String swipe) {
        if (swipe == null) {
            throw new IllegalArgumentException("Swipe data cannot be parsed");
        }
        String[] swipeTokens = parseSwipe(swipe);
        trackOneMasked = swipeTokens[TRACK_ONE_MASKED_POSITION];
        trackTwoMasked = swipeTokens[TRACK_TWO_MASKED_POSITION];
        deviceSerialNumber = swipeTokens[DEVICE_SERIAL_NUMBER];
        trackOneEncrypted = swipeTokens[TRACK_ONE_ENCRYPTED_POSITION];
        trackTwoEncrypted = swipeTokens[TRACK_TWO_ENCRYPTED_POSITION];
        trackThreeEncrypted = swipeTokens[TRACK_THREE_ENCRYPTED_POSITION];
        ksn = swipeTokens[KSN_POSITION];
        cryptographicAlgorithm = swipeTokens[CRYPTOGRAPHIC_ALGORITHM_POSITION];
        metadata = swipeTokens[METADATA_POSITION];
    }

    private String[] parseSwipe(String swipe) {
        int occurrencesOfPipe = StringUtils.countMatches(swipe, "|");
        if (occurrencesOfPipe != 8) {
            throw new IllegalArgumentException("Swipe must have 9 fields, " + occurrencesOfPipe + 1 + " provided.");
        }
        String[] swipeTokens = new String[9];
        String[] tokenizationResult = swipe.split("\\|");
        for (int i = 0; i <= 8; i++) {
            if (i < tokenizationResult.length) {
                swipeTokens[i] = tokenizationResult[i];
            } else {
                swipeTokens[i] = "";
            }
        }
        return swipeTokens;
    }

    public String getTrackOneMasked() {
        return trackOneMasked;
    }

    public String getTrackTwoMasked() {
        return trackTwoMasked;
    }

    public String getDeviceSerialNumber() {
        return deviceSerialNumber;
    }

    public String getTrackOneEncrypted() {
        return trackOneEncrypted;
    }

    public String getTrackTwoEncrypted() {
        return trackTwoEncrypted;
    }

    public String getTrackThreeEncrypted() {
        return trackThreeEncrypted;
    }

    public String getKsn() {
        return ksn;
    }

    public String getCryptographicAlgorithm() {
        return cryptographicAlgorithm;
    }

    public String getMetadata() {
        return metadata;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("GenericTerminalParser{");
        sb.append("trackOneMasked='").append(trackOneMasked).append('\'');
        sb.append(", trackTwoMasked='").append(trackTwoMasked).append('\'');
        sb.append(", deviceSerialNumber='").append(deviceSerialNumber).append('\'');
        sb.append(", trackOneEncrypted='").append(trackOneEncrypted).append('\'');
        sb.append(", trackTwoEncrypted='").append(trackTwoEncrypted).append('\'');
        sb.append(", trackThreeEncrypted='").append(trackThreeEncrypted).append('\'');
        sb.append(", ksn='").append(ksn).append('\'');
        sb.append(", cryptographicAlgorithm='").append(cryptographicAlgorithm).append('\'');
        sb.append(", metadata='").append(metadata).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
