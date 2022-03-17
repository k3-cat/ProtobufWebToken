namespace ProtobufWebToken.Pwt;

public record PTokenWrapper {
    public PToken Token { get; internal set; } = null!;
    public String KeyId { get; internal set; } = null!;
    public Byte[] Signature { get; internal set; } = null!;
    public Byte[] RawPayload { get; internal set; } = null!;
}
