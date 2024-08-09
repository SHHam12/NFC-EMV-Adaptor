package com.github.shham12.myapplication;

import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.github.shham12.nfc_emv_adaptor.EMVParser;
import com.github.shham12.nfc_emv_adaptor.parser.IProvider;
import com.github.shham12.nfc_emv_adaptor.parser.impl.Provider;


import java.nio.charset.StandardCharsets;
import java.util.Map;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "NFC";
    private NfcAdapter nfcAdapter;
    private TextView textView;
    private boolean isNfcEnabled = false;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFilters;
    private String[][] techList;
    private Button nfcButton;
    private AlertDialog nfcDialog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = findViewById(R.id.textView);
        nfcButton = findViewById(R.id.nfcButton);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            Toast.makeText(this, "NFC is not available on this device.", Toast.LENGTH_SHORT).show();
            finish();
        }

        nfcButton.setOnClickListener(v -> {
            if (isNfcEnabled) {
                disableNfc();
            } else {
                enableNfc();
                showNfcDialog();
            }
        });

        Intent intent = new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_MUTABLE);
        intentFilters = new IntentFilter[]{};
        techList = new String[][]{new String[]{IsoDep.class.getName()}};
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (isNfcEnabled) {
            enableNfc();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        disableNfc();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if (tag != null) {
                String[] techList = tag.getTechList();
                boolean isoDepSupported = false;
                for (String tech : techList) {
                    if (tech.equals(IsoDep.class.getName())) {
                        isoDepSupported = true;
                        break;
                    }
                }

                if (isoDepSupported) {
                    readFromNfc(tag);
                } else {
                    Toast.makeText(this, "This NFC tag does not support IsoDep.", Toast.LENGTH_SHORT).show();
                }
            }
        }
    }

    private void enableNfc() {
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFilters, techList);
        nfcButton.setText("Stop NFC");
        isNfcEnabled = true;
    }

    private void disableNfc() {
        nfcAdapter.disableForegroundDispatch(this);
        nfcButton.setText("Start NFC");
        if (nfcDialog != null)
            nfcDialog.dismiss();
        isNfcEnabled = false;
    }

    private void showNfcDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        LayoutInflater inflater = this.getLayoutInflater();
        View dialogView = inflater.inflate(R.layout.dialog_nfc, null);
        builder.setView(dialogView)
                .setCancelable(true)
                .setOnCancelListener(dialog -> disableNfc());
        nfcDialog = builder.create();
        nfcDialog.getWindow().setGravity(Gravity.TOP);

        nfcDialog.show();
    }

    private void readFromNfc(Tag tag) {
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep != null) {
            new Thread(() -> {
                try {
                    isoDep.connect();
                    IProvider temp = new Provider(isoDep);
                    String CAPK = getString(R.string.capk_data);
                    Log.d("JSON", CAPK);
                    EMVParser parser = new EMVParser(temp, true, CAPK);
                    Map<String, byte[]> data = parser.readEmvCard("000000000001");

                    isoDep.close();

                    String value50 = new String(data.get("50"));
                    String value5A = data.containsKey("5A") ? bytesToHex(data.get("5A")) : "N/A";
                    String value57 = data.containsKey("57") ? bytesToHex(data.get("57")) : "N/A";
                    runOnUiThread(() -> {
                        textView.setText("Application Label: " + value50 + "\nCard Number: " + value5A + "\nTrack 2 Data: " + value57);
                    });
                } catch (Exception e) {
                    Log.e(TAG, "Error reading NFC tag", e);
                }
            }).start();
        }
    }

    private void logCommand(byte[] command) {
        runOnUiThread(() -> {
            String hexString = bytesToHex(command);
            textView.append("\nCommand: " + hexString);
            Log.d(TAG, "Command: " + hexString);
        });
    }
    private void logResponse(byte[] response) {
        runOnUiThread(() -> {
            String hexString = bytesToHex(response);
            textView.append("\nResponse: " + hexString);
            Log.d(TAG, "Response: " + hexString);
        });
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
