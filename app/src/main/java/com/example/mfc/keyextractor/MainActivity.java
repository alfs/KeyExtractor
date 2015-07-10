package com.example.mfc.keyextractor;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


    /* Based on code from
    http://mifareclassicdetectiononandroid.blogspot.com/2011/04/reading-mifare-classic-1k-from-android.html
    and
    https://ccsun-fyp.googlecode.com/svn-history/r2/trunk/android/src/com/example/andorid/apis/mifare/MainActivity.java
     */

public class MainActivity extends Activity {

    private static NfcAdapter mAdapter;
    private static PendingIntent mPendingIntent;
    private static IntentFilter[] mFilters;
    private static String[][] mTechLists;

    private static final byte[] HEX_CHAR_TABLE = { (byte) '0', (byte) '1',
            (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6',
            (byte) '7', (byte) '8', (byte) '9', (byte) 'A', (byte) 'B',
            (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F' };

    TextView info;

    public native long mfkey(int uid, int nt, int nt1, int nr0_enc, int ar0_enc, int nr1_enc, int ar1_enc);

    static {
        System.loadLibrary("mfkey");
    }

    public final static String TAG = "KEX";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        info = (TextView) findViewById(R.id.info);

        mAdapter = NfcAdapter.getDefaultAdapter(this);
        mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
                getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);

        try {
            ndef.addDataType("*/*");
        } catch (IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }

        mFilters = new IntentFilter[] { ndef };
        mTechLists = new String[][] { new String[] { MifareClassic.class
                .getName() } };

        Intent intent = getIntent();
        resolveIntent(intent);

    }


    void resolveIntent(Intent intent) {
        // Parse the intent
        String action = intent.getAction();
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
            Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

            NfcA n = NfcA.get(tagFromIntent);

            info.append("\n* Starting up\n");
            info.append("Connecting\n");
            byte[] data;
            try {
                n.connect();
                info.append("Sending RATS\n");
                byte[] rats={(byte) 0xe0, 0x50}; // cooked mode, no checksum, (byte) 0xbc, (byte) 0xa5};
                byte[] ratsresp = n.transceive(rats);
                info.append("Got RATS " + ratsresp.length + " bytes\n");
                // command to retrieve first log entry
                byte[] cmdFirst={ 0x0a,  0x00,  0x00, (byte) 0xa6, (byte) 0xb0,  0x00,  0x10};

                byte[] respFirst = n.transceive(cmdFirst);
                info.append("First response len = " + respFirst.length);
                if (respFirst.length < 10) {
                    info.append("Reponse is too short. Either this is not a sniffer card, or key capture has failed.. Try again, or try capture again. Finished.\n");
                    return;
                }

                info.setText("Got first resp, should start with 0x0a 0x00!  " + getHexString(respFirst,respFirst.length));

                byte[] cmdSecond={ 0x0b,  0x00,  0x00, (byte) 0xa6, (byte) 0xb0,  0x01,  0x10}; // no checksum,  0x14,  0x1d};

                byte[] respSecond = n.transceive(cmdSecond);

                // byte[] input={(byte) 0xAF, (byte) 0xDE, 0x45, (byte) 0x85, 0x04, 0x6C, 0x02, 0x3D, (byte) 0xAC, 0x6B, (byte) 0x8D, (byte) 0x87, 0x66, (byte) 0xA1, (byte) 0xD4, 0x2A}; // , (byte) 0x90, 0x00};
                byte[] decFirst=decrypt(Arrays.copyOfRange(respFirst, 2, respFirst.length - 2)); // cut first 2 and last 2 (crc) bytes
                byte[] decSecond=decrypt(Arrays.copyOfRange(respSecond,2,respSecond.length-2));

                byte[] uid= Arrays.copyOfRange(decFirst, 0, 4);
                char keyAB = (char)((decFirst[4])-0x60+65); // convert from 60/61 to 65/66 (ASCII A/B)
                char sector = (char) (decFirst[5]+48); // convert to ASCII (48 = offset for '0'
                byte[] noncekey0 = Arrays.copyOfRange(decFirst, 6, 8);
                byte[] noncekey1 = Arrays.copyOfRange(decSecond, 6, 8);

                Log.d(TAG,"getnonce nt0 " + getHexString(noncekey0,2));
                Log.d(TAG,"getnonce nt1 " + getHexString(noncekey1,2));

                byte[] nt0=getNonce(new BigInteger(1, noncekey0).intValue());
                byte[] nt1=getNonce(new BigInteger(1, noncekey1).intValue());

                byte[] nr0 = Arrays.copyOfRange(decFirst, 8, 12);
                byte[] ar0 = Arrays.copyOfRange(decFirst, 12, 16);

                byte[] nr1 = Arrays.copyOfRange(decSecond, 8, 12);
                byte[] ar1 = Arrays.copyOfRange(decSecond, 12, 16);

                Log.d(TAG, "./mfkey32 " + getHexString2(uid, uid.length) +
                        " " + getHexString2(nt0, nt0.length) +
                        " " + getHexString2(nr0, nr0.length) +
                        " " + getHexString2(ar0, ar0.length) +
                        " " + getHexString2(nt1, nt1.length) +
                        " " + getHexString2(nr1, nr1.length) +
                        " " + getHexString2(ar1, ar1.length));


                info.append("Card ID: " + getHexString(uid, uid.length) + "\n");

                long key = mfkey(new BigInteger(uid).intValue(),
                        new BigInteger(nt0).intValue(),
                        new BigInteger(nt1).intValue(),
                        new BigInteger(nr0).intValue(),
                        new BigInteger(ar0).intValue(),
                        new BigInteger(nr1).intValue(),
                        new BigInteger(ar1).intValue());

                info.append("Key " + keyAB + " sector " + sector + " is " + Long.toHexString(key) + "\n");

                ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("Key"+keyAB+" sec "+sector, Long.toHexString(key));
                clipboard.setPrimaryClip(clip);

                TextView it = (TextView) findViewById(R.id.infoText);
                it.setText("Found key " + Long.toHexString(key) + " (automatically copied to clipboard)");


            } catch (IOException e) {
                Log.e(TAG, "ioexception" + e.getLocalizedMessage());
                info.append("Exception " + e.getLocalizedMessage() + "\nTry more readings.");
            }
        } else {
            //status_Data.setText("Online + Scan a tag");
        }
    }



    public static String getHexString2(byte[] raw, int len) {
        byte[] hex = new byte[2*len];
        int index = 0;
        int pos = 0;

        for (byte b : raw) {
            if (pos >= len)
                break;

            pos++;
            int v = b & 0xFF;

            hex[index++] = HEX_CHAR_TABLE[v >>> 4];
            hex[index++] = HEX_CHAR_TABLE[v & 0xF];
        }
        return new String(hex);
    }

    public static String getHexString(byte[] raw, int len) {
        byte[] hex = new byte[6 * len]; // aa -> '0xaa '
        int index = 0;
        int pos = 0;

        for (byte b : raw) {
            if (pos >= len)
                break;

            pos++;
            int v = b & 0xFF;

            hex[index++] = '0';
            hex[index++] = 'x';
            hex[index++] = HEX_CHAR_TABLE[v >>> 4];
            hex[index++] = HEX_CHAR_TABLE[v & 0xF];
            hex[index++] = ',';
            hex[index++] = ' ';
        }

        return new String(hex);
    }


    public byte[] decrypt(byte[] input) {

        byte[] keyBytes= new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88};
        byte[] plainText=new byte[]{0};
        try {
            SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");

            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key);
            int ctLength = input.length;
            plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(input, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);

        } catch (Exception e) {
            Log.d(TAG, "Cipher getInstance Exception " + e.getMessage());
        }
        return plainText;
    }


    public byte[] getNonce(int key) {

        byte[] nonce = {0,0,0,0};

        try {
            InputStream inStream = getResources().openRawResource(R.raw.table);
            byte[] nonceTable = new byte[inStream.available()];
            inStream.read(nonceTable);

            // nonceTable maps two bytes into four
            nonce[0] = nonceTable[4*key+3];
            nonce[1] = nonceTable[4*key+2];
            nonce[2] = nonceTable[4*key+1];
            nonce[3] = nonceTable[4*key+0];


        } catch (Exception e) {
            Log.d(TAG, "Exception when loading nonce table " + e.getMessage());
        }
        return nonce;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }


    @Override
    public void onResume() {
        super.onResume();
        mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters,
                mTechLists);
    }

    @Override
    public void onNewIntent(Intent intent) {


        resolveIntent(intent);
    }

}
