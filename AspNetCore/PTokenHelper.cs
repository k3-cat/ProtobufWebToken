using Microsoft.Extensions.Options;
using ProtobufWebToken.Pwt;

namespace ProtobufWebToken.AspNetCore;

public class PTokenHelper {
    readonly IOptionsMonitor<PwtBearerOptions> _optionsMonitor;
    public PwtBearerOptions Options => _optionsMonitor.CurrentValue;

    public PTokenHelper(IOptionsMonitor<PwtBearerOptions> optionsMonitor) {
        _optionsMonitor = optionsMonitor;
    }

    public String CreateToken(PTokenDescriptor descriptor) {
        descriptor.PrivateKey = Options.SigningKey;
        return PTokenHandler.CreateToken(descriptor);
    }
}
