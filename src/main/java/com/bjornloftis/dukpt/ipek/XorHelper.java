package com.bjornloftis.dukpt.ipek;

class XorHelper {

    private static final int BIT_LENGTH = 128;

    static String xorKeyComponents(BinaryKeyComponent a, BinaryKeyComponent b, BinaryKeyComponent c) {

        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < BIT_LENGTH; i++) {
            buffer.append(ternaryXor(a.getBinaryValue().substring(i, i + 1),b.getBinaryValue().substring(i, i + 1),c.getBinaryValue().substring(i, i + 1)));
        }
        String result = buffer.toString();

        return convertToHex(result);
    }

    static String ternaryXor(String a, String b, String c) {
        boolean aBit = isTrueOrFalse(a);
        boolean bBit = isTrueOrFalse(b);
        boolean cBit = isTrueOrFalse(c);
        boolean xor = (aBit ^ bBit ^ cBit);
        return xor ? "1" : "0";
    }

    private static boolean isTrueOrFalse(String a) {
        return "0".equals(a) ? false : true;
    }

    private static String convertToHex(String binary){
        int digitNumber = 1;
        int sum = 0;
        StringBuffer buffer = new StringBuffer();
        for(int i = 0; i < binary.length(); i++){
            if(digitNumber == 1)
                sum+=Integer.parseInt(binary.charAt(i) + "")*8;
            else if(digitNumber == 2)
                sum+=Integer.parseInt(binary.charAt(i) + "")*4;
            else if(digitNumber == 3)
                sum+=Integer.parseInt(binary.charAt(i) + "")*2;
            else if(digitNumber == 4 || i < binary.length()+1){
                sum+=Integer.parseInt(binary.charAt(i) + "")*1;
                digitNumber = 0;
                if(sum < 10)
                   buffer.append(sum);
                else if(sum == 10)
                    buffer.append("A");
                else if(sum == 11)
                    buffer.append("B");
                else if(sum == 12)
                    buffer.append("C");
                else if(sum == 13)
                    buffer.append("D");
                else if(sum == 14)
                    buffer.append("E");
                else if(sum == 15)
                    buffer.append("F");
                sum=0;
            }
            digitNumber++;
        }
        return buffer.toString();
    }
}
