using Microsoft.Net.Http.Headers;

namespace ProtobufWebToken.AspNetCore;

public static class PwtBearerDefaults {
    public const String AuthenticationScheme = "PwtBearer";
    public const String HeaderName = HeaderNames.Authorization;
}
