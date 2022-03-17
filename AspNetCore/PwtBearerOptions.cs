using Microsoft.AspNetCore.Authentication;
using ProtobufWebToken.Pwt;
using ProtobufWebToken.Pwt.Key;

namespace ProtobufWebToken.AspNetCore;

public class PwtBearerOptions : AuthenticationSchemeOptions {
    public String HeaderName { get; init; } = PwtBearerDefaults.HeaderName;
    public EcPrivateKey SigningKey { internal get; set; } = null!;
    public Dictionary<String, EcPublicKey> SigningKeys { get; private init; } = new();
    public PTokenValidationParmeters ValidationParmeters { get; private init; } = new();
}
