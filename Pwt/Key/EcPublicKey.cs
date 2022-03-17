using System.Security.Cryptography;
using System.Text;

namespace ProtobufWebToken.Pwt.Key;

public record EcPublicKey {
    public String KeyId { get; private set; } = null!;
    public ECCurve Curve { get; init; }
    public HashAlgorithmName HashAlgorithm { get; init; }
    public Byte[] PublicKey { get; private set; } = null!;

    EcPublicKey(String curveOid, String hashALgOid) {
        Curve = ECCurve.CreateFromValue(curveOid);
        HashAlgorithm = HashAlgorithmName.FromOid(hashALgOid);
    }

    public EcPublicKey(String curveOid, String hashALgOid, String publicKey) : this(curveOid, hashALgOid) {
        PublicKey = Convert.FromBase64String(publicKey);

        _GenKeyId(curveOid, hashALgOid);
    }

    public EcPublicKey(String curveOid, String hashALgOid, Byte[] privateKey) : this(curveOid, hashALgOid) {
        using var ecdsa = ECDsa.Create(Curve);
        ecdsa.ImportECPrivateKey(privateKey, out _);
        PublicKey = ecdsa.ExportSubjectPublicKeyInfo();

        _GenKeyId(curveOid, hashALgOid);
    }

    void _GenKeyId(String curveOid, String hashALgOid) {
        var alg = Encoding.ASCII.GetBytes($"{curveOid}+{hashALgOid}");
        using var sha256 = SHA256.Create();
        sha256.TransformBlock(alg, 0, alg.Length, alg, 0);
        sha256.TransformFinalBlock(PublicKey, 0, PublicKey.Length);

        KeyId = Convert.ToBase64String(sha256.Hash!);
    }
}
