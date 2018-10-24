package com.bjornloftis.dukpt.ipek;


import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BaseDerivationKey {

    private final List<HexKeyComponent> keyComponents;
    private final String checkValue;

    public BaseDerivationKey(List<HexKeyComponent> components, String checkValue){
        keyComponents = Collections.unmodifiableList(new ArrayList<>(components));
        this.checkValue = checkValue;
    }

    public List<HexKeyComponent> getKeyComponents(){
        return keyComponents;
    }

    public String getCheckValue() {
        return checkValue;
    }


    @Override
    public String toString() {
        return "BaseDerivationKey{" +
                "keyComponents=" + keyComponents +
                ", checkValue='" + checkValue + '\'' +
                '}';
    }
}
