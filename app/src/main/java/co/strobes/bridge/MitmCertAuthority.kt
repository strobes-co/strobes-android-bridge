package co.strobes.bridge

import android.content.Context
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * Root CA for the embedded MITM proxy, plus on-demand per-host leaf certs.
 *
 * Android's stock javax.security APIs can verify X.509 certs but not issue
 * them, so cert generation goes through Bouncy Castle. The CA keypair is
 * generated once and kept in this app's private files dir — Keystore-backed
 * signing was considered and skipped: the whole feature already requires
 * root, so a Keystore boundary buys nothing here, and a plain private key
 * is what lets a single ContentSigner sign arbitrary per-host leaf certs
 * without per-key Keystore ceremony.
 */
class MitmCertAuthority(context: Context) {

    companion object {
        private const val CA_CERT_FILE = "mitm_ca.crt"
        private const val CA_KEY_FILE = "mitm_ca_key.der"
        private const val CA_SUBJECT = "CN=Strobes Bridge MITM CA, O=Strobes"
        private const val VALID_YEARS_CA = 10L
        private const val VALID_YEARS_LEAF = 2L

        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }
    }

    private val caCertFile = File(context.filesDir, CA_CERT_FILE)
    private val caKeyFile = File(context.filesDir, CA_KEY_FILE)
    private val leafCache = ConcurrentHashMap<String, Pair<X509Certificate, PrivateKey>>()

    val caCert: X509Certificate
    private val caKey: PrivateKey

    init {
        if (!caCertFile.exists() || !caKeyFile.exists()) {
            val (cert, key) = generateCa()
            caCertFile.writeBytes(cert.encoded)
            caKeyFile.writeBytes(key.private.encoded)
        }
        val cf = CertificateFactory.getInstance("X.509")
        caCert = cf.generateCertificate(caCertFile.inputStream()) as X509Certificate
        val keyFactory = java.security.KeyFactory.getInstance("RSA")
        caKey = keyFactory.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(caKeyFile.readBytes()))
    }

    /** PEM encoding of the CA cert — what actually gets installed into the trust store. */
    fun caCertPem(): String {
        val b64 = android.util.Base64.encodeToString(caCert.encoded, android.util.Base64.NO_WRAP)
        val wrapped = b64.chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$wrapped\n-----END CERTIFICATE-----\n"
    }

    /**
     * Android's cacerts directory names files by the OpenSSL "subject hash
     * old" convention: the first 4 bytes of MD5(subject DER), read as a
     * little-endian uint32, formatted as 8 lowercase hex chars + ".0". For a
     * cert we generate ourselves with plain UTF8String fields (no legacy
     * T61/BMPString ambiguity), this matches the "old" and "new" hash forms
     * alike, which is what real subject_hash_old implementations reduce to
     * in that case.
     */
    fun subjectHashOldFileName(): String {
        val subjectDer = caCert.subjectX500Principal.encoded
        val md5 = MessageDigest.getInstance("MD5").digest(subjectDer)
        val hash = (md5[0].toInt() and 0xff) or
            ((md5[1].toInt() and 0xff) shl 8) or
            ((md5[2].toInt() and 0xff) shl 16) or
            ((md5[3].toInt() and 0xff) shl 24)
        return String.format("%08x.0", hash)
    }

    /** Generates (or returns the cached) leaf cert+key for one host, signed by our CA. */
    fun leafFor(host: String): Pair<X509Certificate, PrivateKey> {
        return leafCache.getOrPut(host) { generateLeaf(host) }
    }

    private fun generateCa(): Pair<X509Certificate, KeyPair> {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000L)
        val notAfter = Date(now + VALID_YEARS_CA * 365L * 24 * 3600 * 1000)
        val subject = X500Name(CA_SUBJECT)
        val serial = BigInteger.valueOf(now)

        val builder = JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.public)
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(
            Extension.keyUsage, true,
            KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign or KeyUsage.digitalSignature),
        )

        val signer = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.private)
        val certHolder = builder.build(signer)
        val cert = JcaX509CertificateConverter().getCertificate(certHolder)
        return cert to keyPair
    }

    private fun generateLeaf(host: String): Pair<X509Certificate, PrivateKey> {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000L)
        val notAfter = Date(now + VALID_YEARS_LEAF * 365L * 24 * 3600 * 1000)
        // Must be the CA's subject DN with byte-identical ASN.1 encoding, not
        // a round-trip through Java's X500Principal string form — re-parsing
        // that string with BC's X500Name(String) can reorder/re-escape RDNs,
        // which breaks issuer/subject DN matching during chain validation
        // (Android's path builder rejected this with "Trust anchor for
        // certification path not found" despite the CA being genuinely
        // installed and trusted — confirmed live against a real httpbin.org
        // POST before this fix).
        val issuer = JcaX509CertificateHolder(caCert).subject
        val subject = X500Name("CN=$host")
        val serial = BigInteger.valueOf(now + host.hashCode().toLong())

        val builder = JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, keyPair.public)
        builder.addExtension(Extension.basicConstraints, false, BasicConstraints(false))
        builder.addExtension(
            Extension.keyUsage, true,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment),
        )
        builder.addExtension(
            Extension.extendedKeyUsage, false,
            ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth)),
        )
        builder.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(GeneralName(GeneralName.dNSName, host)),
        )

        val signer = JcaContentSignerBuilder("SHA256WithRSA").build(caKey)
        val certHolder = builder.build(signer)
        val cert = JcaX509CertificateConverter().getCertificate(certHolder)
        return cert to keyPair.private
    }
}
