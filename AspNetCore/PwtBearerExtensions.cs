using Microsoft.AspNetCore.Authentication;
using ProtobufWebToken.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

public static class PwtBearerExtensions {
    public static AuthenticationBuilder AddPwtBearer(this AuthenticationBuilder builder) {
        return builder.AddPwtBearer(PwtBearerDefaults.AuthenticationScheme, _ => { });
    }

    public static AuthenticationBuilder AddPwtBearer(this AuthenticationBuilder builder, Action<PwtBearerOptions> configureOptions) {
        return builder.AddPwtBearer(PwtBearerDefaults.AuthenticationScheme, configureOptions);
    }

    public static AuthenticationBuilder AddPwtBearer(this AuthenticationBuilder builder, String authenticationScheme, Action<PwtBearerOptions> configureOptions) {
        return builder.AddPwtBearer(authenticationScheme, null, configureOptions);
    }

    public static AuthenticationBuilder AddPwtBearer(this AuthenticationBuilder builder, String authenticationScheme, String? displayName, Action<PwtBearerOptions> configureOptions) {
        return builder.AddScheme<PwtBearerOptions, AuthHandler>(authenticationScheme, displayName, configureOptions);
    }
}
