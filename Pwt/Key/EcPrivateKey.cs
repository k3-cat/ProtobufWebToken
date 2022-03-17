namespace ProtobufWebToken.Pwt.Key;

public record EcPrivateKey : EcPublicKey {
    public Byte[] PrivateKey { internal get; init; }

    public EcPrivateKey(String curveOid, String hashALgOid, String privateKey) : this(curveOid, hashALgOid, Convert.FromBase64String(privateKey)) {
    }

    public EcPrivateKey(String curveOid, String hashALgOid, Byte[] privateKey) : base(curveOid, hashALgOid, privateKey) {
        PrivateKey = privateKey;
    }
}
