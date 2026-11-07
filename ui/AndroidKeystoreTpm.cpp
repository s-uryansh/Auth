// Hardware-backed Protocol 4 device signer for Android, using a
// non-exportable EC P-256 key inside the Android KeyStore. On supported
// devices the key material is held by the StrongBox/TEE secure element —
// the paper's TPM equivalent (TMPS_Auth.pdf Section IV-C). User
// authentication (device PIN, credential or biometric) within the last
// minute is enforced by the keystore before signing.
#include "AndroidKeystoreTpm.h"

#include "auth/ecdsa_wire.hpp"

#include <QString>

#include <stdexcept>
#include <string>
#include <vector>

#ifdef Q_OS_ANDROID

#include <QJniEnvironment>
#include <QJniObject>

namespace {

constexpr const char* kKeyAlias = "org.tmps.auth.device-key";
constexpr int kSignVerifyPurposes = 3;  // PURPOSE_SIGN | PURPOSE_VERIFY
constexpr int kUserAuthValiditySeconds = 60;

std::runtime_error jniFailure(const QString& stage, const QString& detail = {}) {
    return std::runtime_error(
        (detail.isEmpty() ? stage : QStringLiteral("%1: %2").arg(stage, detail))
            .toStdString());
}

QJniObject javaBytes(const std::vector<uint8_t>& data) {
    QJniEnvironment env;
    jbyteArray array = env->NewByteArray(static_cast<jsize>(data.size()));
    if (!array) throw jniFailure(QStringLiteral("could not allocate byte array"));
    env->SetByteArrayRegion(array, 0, static_cast<jsize>(data.size()),
                            reinterpret_cast<const jbyte*>(data.data()));
    QJniObject result(array);
    env->DeleteLocalRef(array);
    return result;
}

std::vector<uint8_t> nativeBytes(const QJniObject& array) {
    if (!array.isValid()) throw jniFailure(QStringLiteral("missing byte array"));
    QJniEnvironment env;
    jbyteArray java_array = array.object<jbyteArray>();
    const jsize len = env->GetArrayLength(java_array);
    std::vector<uint8_t> out(static_cast<size_t>(len));
    if (len > 0) {
        env->GetByteArrayRegion(java_array, 0, len,
                                reinterpret_cast<jbyte*>(out.data()));
    }
    return out;
}

bool exceptionRaised() {
    QJniEnvironment env;
    if (env->ExceptionOccurred()) {
        env->ExceptionClear();
        return true;
    }
    return false;
}

QJniObject jString(const QString& value) {
    return QJniObject::fromString(value);
}

QJniObject keyStoreInstance() {
    QJniObject ks = QJniObject::callStaticObjectMethod(
        "java/security/KeyStore", "getInstance",
        "(Ljava/lang/String;)Ljava/security/KeyStore;",
        jString(QStringLiteral("AndroidKeyStore")).object<jstring>());
    if (!ks.isValid()) return QJniObject();
    ks.callMethod<void>("load",
                        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
                        QJniObject().object());  // load(null)
    if (exceptionRaised()) return QJniObject();
    return ks;
}

QJniObject signatureInstance(const QString& algorithm,
                             const QString& provider = {}) {
    if (provider.isEmpty()) {
        return QJniObject::callStaticObjectMethod(
            "java/security/Signature", "getInstance",
            "(Ljava/lang/String;)Ljava/security/Signature;",
            jString(algorithm).object<jstring>());
    }
    return QJniObject::callStaticObjectMethod(
        "java/security/Signature", "getInstance",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/Signature;",
        jString(algorithm).object<jstring>(), jString(provider).object<jstring>());
}

QJniObject buildKeySpec(const QJniObject& alias, const QJniObject& ecSpec) {
    QJniEnvironment env;
    jclass builder_class = env->FindClass(
        "android/security/keystore/KeyGenParameterSpec$Builder");
    if (!builder_class) return QJniObject();
    jmethodID ctor = env->GetMethodID(
        builder_class, "<init>",
        "(Ljava/lang/String;ILjava/security/spec/AlgorithmParameterSpec;)V");
    if (!ctor) return QJniObject();
    jobject builder = env->NewObject(builder_class, ctor,
                                     alias.object<jstring>(),
                                     static_cast<jint>(kSignVerifyPurposes),
                                     ecSpec.object());
    if (!builder || exceptionRaised()) return QJniObject();
    return QJniObject(builder);
}

}  // namespace

class AndroidKeystoreTpm final : public auth::sync::TpmInterface {
public:
    explicit AndroidKeystoreTpm(QString& error) {
        QJniObject ks = keyStoreInstance();
        available_ = ks.isValid();
        if (!available_) {
            error = QStringLiteral(
                "AndroidKeyStore is unavailable on this device, so hardware-"
                "backed pairing is disabled.");
        }
    }

    bool hasTPM() const override { return available_; }

    const char* backendName() const noexcept override {
        return "Android KeyStore (hardware-backed secure element)";
    }

    void createKey() override {
        QString error;
        if (!ensureKeyPair(error)) {
            throw error.isEmpty()
                      ? std::runtime_error("Android device key unavailable")
                      : std::runtime_error(error.toStdString());
        }
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) override {
        QString error;
        if (!ensureKeyPair(error)) throw jniFailure(QStringLiteral("device key"), error);

        QJniObject ks = keyStoreInstance();
        if (!ks.isValid()) throw jniFailure(QStringLiteral("keystore closed"));
        QJniObject alias = jString(QString::fromUtf8(kKeyAlias));
        QJniObject priv = ks.callObjectMethod(
            "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;",
            alias.object<jstring>(), QJniObject().object());
        if (!priv.isValid()) throw jniFailure(QStringLiteral("could not read the device key"));

        QJniObject signature =
            signatureInstance(QStringLiteral("SHA256withECDSA"),
                              QStringLiteral("AndroidKeyStore"));
        if (!signature.isValid()) throw jniFailure(QStringLiteral("Signature unavailable"));

        signature.callMethod<void>("initSign",
                                   "(Ljava/security/PrivateKey;)V",
                                   priv.object());
        if (exceptionRaised()) {
            throw jniFailure(QStringLiteral("Signing needs a recent device unlock"),
                             QStringLiteral("Confirm your PIN, password or "
                                            "biometric within the last minute "
                                            "and approve again."));
        }
        signature.callMethod<void>("update", "([B)V",
                                   javaBytes(message).object());
        QJniObject der = signature.callObjectMethod("sign", "()[B");
        if (!der.isValid() || exceptionRaised()) {
            throw jniFailure(QStringLiteral("device signing failed"));
        }
        return auth::sync::ecdsaDerSignatureToRaw(nativeBytes(der));
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& raw_signature,
                const std::vector<uint8_t>& public_key) override {
        const std::vector<uint8_t> der_sig =
            auth::sync::ecdsaRawSignatureToDer(raw_signature);
        std::vector<uint8_t> der_point;
        if (public_key.size() == 65 && public_key[0] == 0x04) {
            der_point = auth::sync::ecdsaPublicKeyPointToDer(public_key);
        } else if (public_key.size() > 65 && public_key[0] == 0x30) {
            der_point = public_key;  // already SPKI DER
        }
        if (der_sig.empty() || der_point.empty()) return false;

        QJniObject key_factory = QJniObject::callStaticObjectMethod(
            "java/security/KeyFactory", "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyFactory;",
            jString(QStringLiteral("EC")).object<jstring>());
        if (!key_factory.isValid() || exceptionRaised()) return false;

        QJniObject spec("java/security/spec/X509EncodedKeySpec", "([B)V",
                        javaBytes(der_point).object());
        if (!spec.isValid() || exceptionRaised()) return false;
        QJniObject pub = key_factory.callObjectMethod(
            "generatePublic",
            "(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;",
            spec.object());
        if (!pub.isValid() || exceptionRaised()) return false;

        QJniObject signature = signatureInstance(QStringLiteral("SHA256withECDSA"));
        if (!signature.isValid()) return false;
        signature.callMethod<void>("initVerify", "(Ljava/security/PublicKey;)V",
                                   pub.object());
        if (exceptionRaised()) return false;
        signature.callMethod<void>("update", "([B)V", javaBytes(message).object());
        const jboolean valid = signature.callMethod<jboolean>(
            "verify", "([B)Z", javaBytes(der_sig).object());
        if (exceptionRaised()) return false;
        return valid == JNI_TRUE;
    }

    std::vector<uint8_t> getPubkey() const override { return pubkey_; }

    void wipe() override {
        // The private key is resident in the hardware keystore and is never
        // exported; the Protocol 4 device identity deliberately survives the
        // session, so there is nothing to wipe beyond the cached public key.
        pubkey_.clear();
    }

private:
    bool ensureKeyPair(QString& error) {
        if (!pubkey_.empty()) return true;
        QJniObject ks = keyStoreInstance();
        if (!ks.isValid()) {
            error = QStringLiteral("AndroidKeyStore is unavailable");
            return false;
        }
        QJniObject alias = jString(QString::fromUtf8(kKeyAlias));
        const jboolean exists = ks.callMethod<jboolean>(
            "containsAlias", "(Ljava/lang/String;)Z", alias.object<jstring>());
        if (exceptionRaised()) return false;

        if (!exists) {
            QJniObject ec_spec("java/security/spec/ECGenParameterSpec",
                               "(Ljava/lang/String;)V",
                               jString(QStringLiteral("secp256r1")).object<jstring>());
            if (!ec_spec.isValid() || exceptionRaised()) {
                error = QStringLiteral("EC curve spec unavailable");
                return false;
            }
            QJniObject builder = buildKeySpec(alias, ec_spec);
            if (!builder.isValid()) {
                error = QStringLiteral(
                    "Could not configure the device key builder");
                return false;
            }
            builder = builder.callObjectMethod(
                "setUserAuthenticationRequired",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                JNI_TRUE);
            builder = builder.callObjectMethod(
                "setUserAuthenticationValidityDurationSeconds",
                "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                static_cast<jint>(kUserAuthValiditySeconds));
            QJniObject spec = builder.callObjectMethod(
                "build", "()Landroid/security/keystore/KeyGenParameterSpec;");
            if (!spec.isValid() || exceptionRaised()) {
                error = QStringLiteral(
                    "Device key requires a secure lock screen: enable a PIN, "
                    "pattern, password or biometric, then try again");
                return false;
            }
            QJniObject generator = QJniObject::callStaticObjectMethod(
                "java/security/KeyPairGenerator", "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)"
                "Ljava/security/KeyPairGenerator;",
                jString(QStringLiteral("EC")).object<jstring>(),
                jString(QStringLiteral("AndroidKeyStore")).object<jstring>());
            if (!generator.isValid() || exceptionRaised()) {
                error = QStringLiteral("AndroidKeyStore EC keys are unavailable");
                return false;
            }
            generator.callMethod<void>(
                "initialize",
                "(Ljava/security/spec/AlgorithmParameterSpec;)V",
                spec.object());
            if (exceptionRaised()) {
                error = QStringLiteral("Device key initialization failed");
                return false;
            }
            generator.callObjectMethod(
                "generateKeyPair",
                "()Ljava/security/KeyPairGenerator$KeyPair;");
            if (exceptionRaised()) {
                error = QStringLiteral("Device key creation failed");
                return false;
            }
        }

        QJniObject certificate = ks.callObjectMethod(
            "getCertificate",
            "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
            alias.object<jstring>());
        if (!certificate.isValid() || exceptionRaised()) {
            error = QStringLiteral("Device certificate missing");
            return false;
        }
        QJniObject pub =
            certificate.callObjectMethod("getPublicKey", "()Ljava/security/PublicKey;");
        QJniObject der = pub.callObjectMethod("getEncoded", "()[B");
        if (!der.isValid() || exceptionRaised()) {
            error = QStringLiteral("Device public key export failed");
            return false;
        }
        const std::vector<uint8_t> point =
            auth::sync::ecdsaDerPublicKeyToPoint(nativeBytes(der));
        if (point.empty()) {
            error = QStringLiteral("Device key is not a P-256 public key");
            return false;
        }
        pubkey_ = point;
        return true;
    }

    bool available_ = false;
    std::vector<uint8_t> pubkey_;
};

std::unique_ptr<auth::sync::TpmInterface> createAndroidKeystoreSigner(
    QString& error) {
    auto signer = std::make_unique<AndroidKeystoreTpm>(error);
    if (!signer->hasTPM()) return nullptr;
    return signer;
}

#else  // !Q_OS_ANDROID

std::unique_ptr<auth::sync::TpmInterface> createAndroidKeystoreSigner(
    QString& error) {
    error = QStringLiteral("Android KeyStore signer is only built for Android");
    return nullptr;
}

#endif
