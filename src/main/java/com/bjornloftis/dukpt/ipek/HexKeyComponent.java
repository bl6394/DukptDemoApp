package com.bjornloftis.dukpt.ipek;

public class HexKeyComponent {

    private final String component;
    private final String checkValue;

    public HexKeyComponent(String keyComponent, String checkValue) {
        this.component = keyComponent;
        this.checkValue = checkValue;
    }

    public String getComponent() {
        return component;
    }

    public String getCheckValue() {
        return checkValue;
    }


    @Override
    public String toString() {
        return "BinaryKeyComponent{" +
                "component='" + component + '\'' +
                ", checkValue='" + checkValue + '\'' +
                '}';
    }

}
