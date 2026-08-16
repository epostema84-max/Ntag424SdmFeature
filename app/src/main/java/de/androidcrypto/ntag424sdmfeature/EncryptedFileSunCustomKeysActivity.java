package de.androidcrypto.ntag424sdmfeature;

import static net.bplearning.ntag424.CommandResult.PERMISSION_DENIED;
import static net.bplearning.ntag424.constants.Ntag424.NDEF_FILE_NUMBER;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_EVERYONE;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY0;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY2;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY3;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_KEY4;
import static net.bplearning.ntag424.constants.Permissions.ACCESS_NONE;

import android.content.Context;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.RadioButton;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.ChangeFileSettings;
import net.bplearning.ntag424.command.ChangeKey;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.WriteData;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.encryptionmode.LRPEncryptionMode;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class EncryptedFileSunCustomKeysActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    /* ================================================================
       HIER AANPASSEN — dit zijn de enige regels die je hoeft te wijzigen
       ================================================================ */

    // De URL die in de tag komt. Deze is definitief: wijzigen betekent
    // elke sticker opnieuw programmeren.
    private static final String KLOK_URL =
            "https://klok.divoza.nl/t.php?p={PICC}&c={MAC}";

    // Sleutel 3 = SDM Meta Read. Vul deze in het beheer in als meta-sleutel.
    private static final String KLOK_SLEUTEL_META =
            "9fe3e4e2ffc6c8b95753cfc11f7f862f";

    // Sleutel 4 = SDM File Read. Vul deze in het beheer in als file-sleutel.
    private static final String KLOK_SLEUTEL_FILE =
            "a7ea5efb888fd2112b1857fb7c09aa9f";

    // Geef elke sticker zijn eigen sleutelpaar: nieuwe waarden genereren met
    //   openssl rand -hex 16
    // of overnemen uit admin.php bij Tags.

    private static final int KLOK_SLEUTEL_VERSIE = 1;

    /* ================================================================ */

    private static final String TAG = EncryptedFileSunCustomKeysActivity.class.getSimpleName();
    private com.google.android.material.textfield.TextInputEditText output;
    private RadioButton rbUid, rbCounter, rbUidCounter;
    private DnaCommunicator dnaC = new DnaCommunicator();
    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    /** Zet 32 hextekens om naar 16 bytes. */
    private static byte[] hexNaarBytes(String hex) {
        hex = hex.trim().replaceAll("[^0-9a-fA-F]", "");
        int lengte = hex.length() / 2;
        byte[] uit = new byte[lengte];
        for (int i = 0; i < lengte; i++) {
            uit[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return uit;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_encrypted_file_sun_custom_keys);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        rbUid = findViewById(R.id.rbFieldUid);
        rbCounter = findViewById(R.id.rbFieldCounter);
        rbUidCounter = findViewById(R.id.rbFieldUidCounter);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void vibrateShort() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * NFC tag handling section
     */

    @Override
    public void onTagDiscovered(Tag tag) {

        writeToUiAppend(output, "NFC tag discovered");

        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                });

                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppend(output, "Could not connect to the tag, aborted");
                    isoDep.close();
                    return;
                }

                tagIdByte = tag.getId();
                writeToUiAppend(output, "Tag ID: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppend(output, "NFC tag connected");

                runWorker();
            }

        } catch (IOException e) {
            writeToUiAppend(output, "ERROR: IOException " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppend(output, "ERROR: Exception " + e.getMessage());
            e.printStackTrace();
        }

    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {
            Bundle options = new Bundle();
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null) {
            mNfcAdapter.disableReaderMode(this);
        }
    }

    /** Wisselt een sleutel; lukt dat niet met de fabriekssleutel, dan stond hij er al op. */
    private boolean sleutelZetten(int keyNummer, byte[] nieuweSleutel, boolean lrpModus) {
        try {
            ChangeKey.run(dnaC, keyNummer, Ntag424.FACTORY_KEY, nieuweSleutel, KLOK_SLEUTEL_VERSIE);
            writeToUiAppend(output, "Sleutel " + keyNummer + " gezet (was fabrieksinstelling)");
            return true;
        } catch (Exception e) {
            Log.d(TAG, "ChangeKey " + keyNummer + " met fabriekssleutel mislukt: " + e.getMessage());
        }
        // Opnieuw authenticeren, want de mislukte poging kan de sessie verstoord hebben.
        try {
            boolean ok = lrpModus
                    ? LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY)
                    : AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
            if (!ok) {
                writeToUiAppend(output, "Sleutel " + keyNummer + ": herauthenticatie mislukt");
                return false;
            }
            ChangeKey.run(dnaC, keyNummer, nieuweSleutel, nieuweSleutel, KLOK_SLEUTEL_VERSIE);
            writeToUiAppend(output, "Sleutel " + keyNummer + " stond er al op, ongewijzigd");
            return true;
        } catch (Exception e) {
            writeToUiAppend(output, "Sleutel " + keyNummer + " FOUT: " + e.getMessage());
            return false;
        }
    }

    private void runWorker() {
        Log.d(TAG, "Klok tag programmeren");
        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                boolean success = false;
                try {
                    dnaC = new DnaCommunicator();
                    try {
                        dnaC.setTransceiver((bytesToSend) -> isoDep.transceive(bytesToSend));
                    } catch (NullPointerException npe) {
                        writeToUiAppend(output, "Please tap a tag before running any tests, aborted");
                        return;
                    }
                    dnaC.setLogger((info) -> Log.d(TAG, "Communicator: " + info));
                    dnaC.beginCommunication();

                    /**
                     * 1) Authenticeren met applicatiesleutel 00h
                     * 2) Sleutel 3 en 4 vervangen door de eigen sleutels
                     * 3) URL-sjabloon naar bestand 02 schrijven (UID + teller + CMAC)
                     * 4) Bestandsinstellingen ophalen en met SDM terugschrijven
                     */

                    boolean isLrpAuthenticationMode = false;

                    success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                    if (success) {
                        writeToUiAppend(output, "AES Authentication SUCCESS");
                    } else {
                        if (dnaC.getLastCommandResult().status2 == PERMISSION_DENIED) {
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY0, Ntag424.FACTORY_KEY);
                            if (success) {
                                writeToUiAppend(output, "LRP Authentication SUCCESS");
                                isLrpAuthenticationMode = true;
                            } else {
                                writeToUiAppend(output, "LRP Authentication FAILURE");
                                writeToUiAppend(output, "returnCode is " + Utils.byteToHex(dnaC.getLastCommandResult().status2));
                                writeToUiAppend(output, "Authentication not possible, Operation aborted");
                                return;
                            }
                        } else {
                            writeToUiAppend(output, "AES Authentication FAILURE");
                            writeToUiAppend(output, "returnCode is " + Utils.byteToHex(dnaC.getLastCommandResult().status2));
                            return;
                        }
                    }

                    // eigen sleutels op de tag zetten
                    byte[] sleutelMeta = hexNaarBytes(KLOK_SLEUTEL_META);
                    byte[] sleutelFile = hexNaarBytes(KLOK_SLEUTEL_FILE);
                    if (sleutelMeta.length != 16 || sleutelFile.length != 16) {
                        writeToUiAppend(output, "FOUT: een sleutel is geen 32 hextekens, aborted");
                        return;
                    }
                    if (!sleutelZetten(ACCESS_KEY3, sleutelMeta, isLrpAuthenticationMode)) return;
                    if (!sleutelZetten(ACCESS_KEY4, sleutelFile, isLrpAuthenticationMode)) return;

                    FileSettings fileSettings02 = null;
                    try {
                        fileSettings02 = GetFileSettings.run(dnaC, NDEF_FILE_NUMBER);
                    } catch (Exception e) {
                        Log.e(TAG, "getFileSettings File 02 Exception: " + e.getMessage());
                        writeToUiAppend(output, "getFileSettings File 02 Exception: " + e.getMessage());
                    }
                    if (fileSettings02 == null) {
                        Log.e(TAG, "getFileSettings File 02 Error, Operation aborted");
                        writeToUiAppend(output, "getFileSettings File 02 Error, Operation aborted");
                        return;
                    }
                    int ACCESS_KEY_RW = fileSettings02.readWritePerm;
                    int ACCESS_KEY_CAR = fileSettings02.changePerm;
                    writeToUiAppend(output, "getFileSettings File 02 AUTH-KEY RW Is: " + ACCESS_KEY_RW);

                    if (ACCESS_KEY_RW == 14) {
                        // vrije schrijftoegang, geen authenticatie nodig
                    } else {
                        if (ACCESS_KEY_RW != ACCESS_KEY0) {
                            if (!isLrpAuthenticationMode) {
                                success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY_RW, Ntag424.FACTORY_KEY);
                            } else {
                                success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY_RW, Ntag424.FACTORY_KEY);
                            }
                            if (!success) {
                                writeToUiAppend(output, "Error on Authentication with key " + ACCESS_KEY_RW + ", aborted");
                                return;
                            }
                        }
                    }

                    // URL-sjabloon schrijven — versleutelde PICC-data plus CMAC, geen bestandsdata
                    SDMSettings sdmSettings = new SDMSettings();
                    sdmSettings.sdmEnabled = true;
                    sdmSettings.sdmMetaReadPerm = ACCESS_KEY3;   // versleutelt UID + teller
                    sdmSettings.sdmFileReadPerm = ACCESS_KEY4;   // zet de handtekening
                    sdmSettings.sdmReadCounterRetrievalPerm = ACCESS_NONE;
                    sdmSettings.sdmOptionEncryptFileData = false;
                    sdmSettings.sdmOptionUid = true;
                    sdmSettings.sdmOptionReadCounter = true;

                    NdefTemplateMaster master = new NdefTemplateMaster();
                    master.usesLRP = isLrpAuthenticationMode;
                    byte[] ndefRecord = master.generateNdefTemplateFromUrlString(KLOK_URL, sdmSettings);

                    try {
                        WriteData.run(dnaC, NDEF_FILE_NUMBER, ndefRecord, 0);
                    } catch (IOException e) {
                        Log.e(TAG, "writeData IOException: " + e.getMessage());
                        writeToUiAppend(output, "File 02h writeDataIOException: " + e.getMessage());
                        writeToUiAppend(output, "Writing the NDEF URL Template FAILURE, Operation aborted");
                        return;
                    }
                    writeToUiAppend(output, "File 02h Writing the NDEF URL Template SUCCESS");

                    if (ACCESS_KEY_CAR != ACCESS_KEY_RW) {
                        if (!isLrpAuthenticationMode) {
                            success = AESEncryptionMode.authenticateEV2(dnaC, ACCESS_KEY_CAR, Ntag424.FACTORY_KEY);
                        } else {
                            success = LRPEncryptionMode.authenticateLRP(dnaC, ACCESS_KEY_CAR, Ntag424.FACTORY_KEY);
                        }
                        if (!success) {
                            writeToUiAppend(output, "Error on Authentication with key " + ACCESS_KEY_CAR + ", aborted");
                            return;
                        }
                    }

                    fileSettings02.sdmSettings = sdmSettings;
                    fileSettings02.readWritePerm = ACCESS_KEY0;
                    fileSettings02.changePerm = ACCESS_KEY0;
                    fileSettings02.readPerm = ACCESS_EVERYONE;   // elke telefoon moet kunnen lezen
                    fileSettings02.writePerm = ACCESS_KEY0;
                    try {
                        ChangeFileSettings.run(dnaC, NDEF_FILE_NUMBER, fileSettings02);
                    } catch (IOException e) {
                        e.printStackTrace();
                        Log.e(TAG, "ChangeFileSettings IOException: " + e.getMessage());
                        writeToUiAppend(output, "ChangeFileSettings File 02 Error, Operation aborted");
                        return;
                    }
                    writeToUiAppend(output, "File 02h Change File Settings SUCCESS");

                    writeToUiAppend(output, "");
                    writeToUiAppend(output, "=== INVULLEN BIJ TAGS IN HET BEHEER ===");
                    writeToUiAppend(output, "UID: " + Utils.bytesToHex(tagIdByte));
                    writeToUiAppend(output, "meta-sleutel: " + KLOK_SLEUTEL_META);
                    writeToUiAppend(output, "file-sleutel: " + KLOK_SLEUTEL_FILE);

                } catch (IOException e) {
                    Log.e(TAG, "Exception: " + e.getMessage());
                    writeToUiAppend(output, "Exception: " + e.getMessage());
                }
                writeToUiAppend(output, "== FINISHED ==");
                vibrateShort();
            }
        });
        worker.start();
    }

    public static String getTimestampLog() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return ZonedDateTime
                    .now(ZoneId.systemDefault())
                    .format(DateTimeFormatter.ofPattern("dd.MM.uuuu HH:mm:ss"));
        } else {
            return new SimpleDateFormat("dd.MM.yyyy HH:mm:ss").format(new Date());
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mReturnHome = menu.findItem(R.id.action_return_home);
        mReturnHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(EncryptedFileSunCustomKeysActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}
