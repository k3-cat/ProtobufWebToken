using ProtobufWebToken.Pwt.Key;

namespace ProtobufWebToken.Pwt;

public record PTokenDescriptor {
    public Guid SubjectId { get; init; }
    public String DisplayName { get; init; } = null!;
    public DateTimeOffset ExpireAt { get; init; }
    public DateTimeOffset ValidFrom { get; init; }
    public IEnumerable<String> Roles { get; init; } = null!;

    public EcPrivateKey PrivateKey { internal get; set; } = null!;
}
