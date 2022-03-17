using ProtobufWebToken.Pwt.Key;

namespace ProtobufWebToken.Pwt;

public delegate DateTimeOffset GetNowDelegate();

public delegate EcPublicKey SigningKeyResloverDelegate(String keyId);

public record PTokenValidationParmeters {
    public GetNowDelegate GetNow { get; set; } = null!;
    public SigningKeyResloverDelegate SigningKeyReslover { get; set; } = null!;
}
