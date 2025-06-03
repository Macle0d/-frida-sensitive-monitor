/*
# Autor: Omar Peña
# Descripción: Script que permite engancharse a un proceso de android e intenta obtener datos sensibles como keys
# Repo: https://github.com/Macle0d/-frida-sensitive-monitor
# Version: 1.0
*/

// ==================== UTILIDADES ====================
function isSensitive(data) {
    if (!data) return false;
    const patterns = [
        /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, // JWT
        /AKIA[0-9A-Z]{16}/, // AWS
        /(?:\d[ -]*?){13,16}/, // tarjetas
        /(?:password|passwd|pwd|key|clave|token|auth|encryptionKey)[^=:\n]*[=:\n][^&\s]+/i,
        /-----BEGIN (RSA|EC|DSA|PRIVATE|ENCRYPTED|OPENSSH) KEY-----/,
        /(?:MIIB|MIIE|MIIK)[A-Za-z0-9+/=\r\n]{100,}/,
        /sha-?512[^a-zA-Z0-9]*[a-fA-F0-9]{128}/i,
        /sha-?256[^a-zA-Z0-9]*[a-fA-F0-9]{64}/i,
        /\$2[aby]\$.{56}/,
        /\$argon2[a-z]*\$.{20,}/,
        /[a-zA-Z0-9+\/]{20,}={0,2}/,
        /\b[A-Za-z0-9+/=#!&*~@%^$.-]{32,}\b/,
        /\bptoken[=:]{1}[^&\s]+/i,
        /"signature"\s*:\s*"([A-Za-z0-9+/=]{50,})"/,
        /"device_id"\s*:\s*"[^"]+"/i,
        /"Device-Uuid"\s*:\s*"[^"]+"/i,
        /otp|totp/i
    ];
    return patterns.some(p => p.test(data));
}

function bytesToHex(bytes) {
    return Array.prototype.map.call(bytes, b => ('0' + (b & 0xff).toString(16))).join('');
}

function log(label, data) {
    const ts = new Date().toISOString();
    console.warn(`\n[!] [${ts}] ${label}:\n${data}`);
    try {
        const stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
        for (let i = 2; i < Math.min(stack.length, 7); i++) {
            console.warn("  at " + stack[i].toString());
        }
    } catch (_) {}
}

function safeUse(className) {
    try {
        return Java.use(className);
    } catch (_) {
        return null;
    }
}

// ==================== JAVA HOOKS ====================
function hookJavaCryptoAndStrings() {
    Java.perform(function () {
        const StringClass = safeUse("java.lang.String");
        const SecretKeySpec = safeUse("javax.crypto.spec.SecretKeySpec");

        if (StringClass) {
            StringClass.$init.overload('[B').implementation = function (bytes) {
                const result = this.$init(bytes);
                const str = this.toString();
                if (isSensitive(str)) log("String(byte[]) sensible", str);
                return result;
            };

            StringClass.$init.overload('java.lang.String').implementation = function (s) {
                const result = this.$init(s);
                if (isSensitive(s)) log("String(String) sensible", s);
                return result;
            };
        }

        if (SecretKeySpec) {
            SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
                const hexKey = bytesToHex(key);
                if (isSensitive(hexKey)) log("SecretKeySpec sensible", `Algoritmo: ${algo}, Clave hex: ${hexKey}`);
                return this.$init(key, algo);
            };
        }
    });
}

function hookSQLCipherKeys() {
    Java.perform(function () {
        const SQLCipher = safeUse("net.sqlcipher.database.SQLiteDatabase");
        if (!SQLCipher) {
            console.warn("[!] Clase SQLCipher no disponible.");
            return;
        }

        SQLCipher.openOrCreateDatabase.overloads.forEach(overload => {
            const sig = overload.argumentTypes.map(t => t.className).join(", ");
            overload.implementation = function () {
                try {
                    const argsLog = [];
                    for (let i = 0; i < arguments.length; i++) {
                        const arg = arguments[i];
                        if (arg && typeof arg === 'string' && isSensitive(arg)) {
                            argsLog.push(`Arg ${i} (String): ${arg}`);
                        } else if (arg && arg.getAbsolutePath) {
                            argsLog.push(`Arg ${i} (File): ${arg.getAbsolutePath()}`);
                        } else if (arg instanceof Array && arg.length >= 16) {
                            argsLog.push(`Arg ${i} (bytes): ${bytesToHex(arg)}`);
                        }
                    }
                    if (argsLog.length > 0) {
                        log(`[SQLCipher] openOrCreateDatabase(${sig})`, argsLog.join('\n'));
                    }
                } catch (e) {
                    console.error("[SQLCipher hook error]:", e);
                }
                return overload.apply(this, arguments);
            };
        });
    });
}

function hookCordovaSQLite() {
    Java.perform(function () {
        const SQLitePlugin = safeUse("org.apache.cordova.sqlite.SQLitePlugin");
        if (!SQLitePlugin) {
            console.warn("[!] Clase SQLitePlugin no disponible.");
            return;
        }

        SQLitePlugin.open.overload('org.json.JSONObject').implementation = function (args) {
            const json = args.toString();
            if (isSensitive(json)) log("[Cordova SQLitePlugin] JSONObject sensible", json);
            return this.open(args);
        };
    });
}

// ==================== MAIN ====================
setImmediate(function () {
    hookJavaCryptoAndStrings();
    hookSQLCipherKeys();
    hookCordovaSQLite();
});
