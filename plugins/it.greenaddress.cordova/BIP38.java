package it.greenaddress.cordova;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;
import com.blockstream.libwally.Wally;
import java.io.UnsupportedEncodingException;
import java.util.concurrent.ExecutorService;

import static com.blockstream.libwally.Wally.BIP38_SERIALISED_LEN;
import static com.blockstream.libwally.Wally.BIP38_KEY_MAINNET;
import static com.blockstream.libwally.Wally.BIP38_KEY_TESTNET;
import static com.blockstream.libwally.Wally.BIP38_KEY_COMPRESSED;
import static com.blockstream.libwally.Wally.BIP38_KEY_RAW_MODE;
import static com.blockstream.libwally.Wally.BIP38_KEY_SWAP_ORDER;

public class BIP38 extends CordovaPlugin
{
    // Syntactic sugar
    protected void runAsync(final Runnable task) {
        cordova.getThreadPool().execute(task);
    }

    // Syntactic sugar for returning an error
    protected static void setError(final CallbackContext cb, final String error) {
        cb.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, error));
    }

    private static void setError(final CallbackContext cb, final Throwable e) {

        String error = "Unknown error";
        if (e instanceof IllegalArgumentException) {
            error = "Invalid argument";
        } else if (e instanceof OutOfMemoryError) {
            error = "Out of memory";
        } else if (e instanceof RuntimeException) {
            error = "Failed";
        } else if (e instanceof UnsupportedEncodingException) {
            error = "Invalid character encoding";
        }
        setError(cb, error);
    };


    // Syntactic sugar for returning string data
    protected static void setString(final CallbackContext cb, final String result) {
        cb.sendPluginResult(new PluginResult(PluginResult.Status.OK, result));
    }

    // Syntactic sugar for returning binary data
    protected static void setBytes(final CallbackContext cb, final byte[] src, int start, int end) {
        final JSONArray j = new JSONArray();
        for (int i = start; i < end; i++) {
            int ubyte = src[i];
            ubyte &= 0xFF;
            j.put(ubyte);
        }
        cb.sendPluginResult(new PluginResult(PluginResult.Status.OK, j));
    }

    // Get bytes from JS into Java format
    protected static byte[] getBytes(final JSONArray args, int n, int expected) throws JSONException {
        final JSONArray j = args.getJSONArray(n);
        if (expected > 0 && j.length() != expected)
            throw new IllegalArgumentException("Unexpected array length");
        final byte[] data = new byte[j.length()];
        for (int i = 0; i < j.length(); ++i)
            data[i] = (byte)j.getInt(i);
        return data;
    }

    // Convert a private key to a BIP 38 key
    private boolean encrypt(final JSONArray args, final CallbackContext cb) throws JSONException {

        final byte[] pk = getBytes(args, 0, 32);
        final String pwd = args.getString(1);
        final String coin = args.getString(2);
        final long flags;
        final Runnable task;

        if (coin.equals("BTC"))
            flags = BIP38_KEY_COMPRESSED | BIP38_KEY_MAINNET;
        else if (coin.equals("BTT"))
            flags = BIP38_KEY_COMPRESSED | BIP38_KEY_TESTNET;
        else {
            BIP38.setError(cb, "InvalidNetwork");
            return true;
        }

        task = new Runnable() {
                   public void run() {
                       try {
                           final byte[] pass = pwd.getBytes("UTF-8");
                           BIP38.setString(cb, Wally.bip38_from_private_key(pk, pass, flags));
                       } catch (Throwable e) {
                           BIP38.setError(cb, e);
                       }
                   }
        };

        runAsync(task);
        return true;
    }

    // Convert a private key to a raw, truncated BIP 38 key
    private boolean encrypt_raw(final JSONArray args, final CallbackContext cb) throws JSONException {

        final long flags = BIP38_KEY_COMPRESSED | BIP38_KEY_RAW_MODE | BIP38_KEY_SWAP_ORDER;
        final byte[] pk = getBytes(args, 0, 32);
        final String pwd = args.getString(1);
        final Runnable task;

        // We skip the first 3 bytes to return a 36 byte block. When we
        // reconstruct the block we will hard code these bytes back in.
        // This works as we always use compressed keys so version/flags
        // are constant.
        task = new Runnable() {
                   public void run() {
                       try {
                           final byte[] pass = pwd.getBytes("UTF-8");
                           final byte[] raw = Wally.bip38_raw_from_private_key(pk, pass, flags, null);
                           BIP38.setBytes(cb, raw, 3, raw.length);
                       } catch (Throwable e) {
                           BIP38.setError(cb, e);
                       }
                   }
        };

        runAsync(task);
        return true;
    }

    // Convert a BIP 38 key to a private key
    private boolean decrypt(final JSONArray args, final CallbackContext cb) throws JSONException {

        final String b58 = args.getString(0);
        final String pwd = args.getString(1);
        final String coin = args.getString(2);
        final long flags;
        final Runnable task;

        if (coin.equals("BTC"))
            flags = BIP38_KEY_COMPRESSED | BIP38_KEY_MAINNET;
        else if (coin.equals("BTT"))
            flags = BIP38_KEY_COMPRESSED | BIP38_KEY_TESTNET;
        else {
            BIP38.setError(cb, "InvalidNetwork");
            return true;
        }

        task = new Runnable() {
                   public void run() {
                       try {
                           final byte[] pass = pwd.getBytes("UTF-8");
                           final byte[] pk = Wally.bip38_to_private_key(b58, pass, flags, null);
                           BIP38.setBytes(cb, pk, 0, pk.length);
                       } catch (Throwable e) {
                           BIP38.setError(cb, e);
                       }
                   }
        };

        runAsync(task);
        return true;
    }

    // Convert a raw, truncated BIP 38 key to a private key
    private boolean decrypt_raw(final JSONArray args, final CallbackContext cb) throws JSONException {

        final JSONArray j = args.getJSONArray(0);
        final byte[] data = new byte[BIP38_SERIALISED_LEN];
        // Reconstruct our original 39 byte block
        data[0] = (byte)0x01; // Version
        data[1] = (byte)0x42; // Non-EC Multiplied
        data[2] = (byte)0xE0; // Flags normal, compressed
        for (int i = 0; i < data.length - 3; ++i)
           data[i + 3] = (byte)j.getInt(i);
        final String pwd = args.getString(1);

        final long flags = BIP38_KEY_COMPRESSED | BIP38_KEY_RAW_MODE | BIP38_KEY_SWAP_ORDER;
        final Runnable task;

        task = new Runnable() {
                   public void run() {
                       try {
                           final byte[] pass = pwd.getBytes("UTF-8");
                           final byte[] pk = Wally.bip38_raw_to_private_key(data, pass, flags, null);
                           BIP38.setBytes(cb, pk, 0, pk.length);
                       } catch (Throwable e) {
                           BIP38.setError(cb, e);
                       }
                   }
        };

        runAsync(task);
        return true;
    }

    private boolean calcSeed(final JSONArray args, final CallbackContext cb) throws JSONException {

        final String password = args.getString(0);
        final String mnemonic = args.getString(1);
        final Runnable task;

        task = new Runnable() {
                   public void run() {
                       try {
                           final byte[] p = password.getBytes("UTF-8");
                           final byte[] m = mnemonic.getBytes("UTF-8");
                           final byte[] seed = Wally.pbkdf2_hmac_sha512(m, p, 0, 2048, null);
                           BIP38.setBytes(cb, seed, 0, seed.length);
                       } catch (Throwable e) {
                           BIP38.setError(cb, e);
                       }
                  }
        };

        runAsync(task);
        return true;
    }

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext cb) throws JSONException {
        if ("encrypt".equals(action)) {
            return encrypt(args, cb);
        } else if ("decrypt".equals(action)) {
            return decrypt(args, cb);
        } else if ("encrypt_raw".equals(action)) {
            return encrypt_raw(args, cb);
        } else if ("decrypt_raw".equals(action)) {
            return decrypt_raw(args, cb);
        } else if ("calcSeed".equals(action)) {
            return calcSeed(args, cb);
        }
        return false;
    }
}
