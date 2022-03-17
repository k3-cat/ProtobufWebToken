using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ProtobufWebToken.Pwt;

namespace ProtobufWebToken.AspNetCore;

public class AuthHandler : AuthenticationHandler<PwtBearerOptions> {
    public AuthHandler(IOptionsMonitor<PwtBearerOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
        : base(options, logger, encoder, clock) {
        options.CurrentValue.ValidationParmeters.GetNow = new GetNowDelegate(() => clock.UtcNow);
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
        var header = Request.Headers[Options.HeaderName].ToString();
        if (String.IsNullOrWhiteSpace(header)) {
            Logger.LogInformation("Anonymous user from {@Address}", Context.Connection.RemoteIpAddress.ToString());
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        ClaimsPrincipal principal;
        try {
            principal = PTokenHandler.ValidateToken(header, Options.ValidationParmeters);
        }
        catch (Exception) {
            Logger.LogWarning("Invalid token from {@Address}", Context.Connection.RemoteIpAddress.ToString());
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
