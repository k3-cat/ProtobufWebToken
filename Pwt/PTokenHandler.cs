using System.Security.Claims;
using System.Security.Cryptography;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;

namespace ProtobufWebToken.Pwt;

public class PTokenHandler {
    public static PTokenWrapper ReadToken(String token) {
        if (String.IsNullOrWhiteSpace(token)) {
            throw new ArgumentNullException(nameof(token));
        }

        var tokenParts = token.Split(Constants.PartSpliter, Constants.SegmentCount + 1);
        if (tokenParts.Length != Constants.SegmentCount) {
            throw new ArgumentException($"Token has incorrect number of parts of {tokenParts.Length} (should be {Constants.SegmentCount}).");
        }

        var raw = Convert.FromBase64String(tokenParts[2]);
        return new PTokenWrapper {
            Token = PToken.Parser.ParseFrom(raw),
            KeyId = tokenParts[0],
            Signature = Convert.FromBase64String(tokenParts[1]),
            RawPayload = raw,
        };
    }

    public static void ValidateSignature(PTokenWrapper tokenWrapper, PTokenValidationParmeters validationParmeters) {
        var pubKey = validationParmeters.SigningKeyReslover(tokenWrapper.KeyId);
        using var ecdsa = ECDsa.Create(pubKey.Curve);
        ecdsa.ImportSubjectPublicKeyInfo(pubKey.PublicKey, out _);
        if (!ecdsa.VerifyData(tokenWrapper.RawPayload, tokenWrapper.Signature, pubKey.HashAlgorithm)) {
            throw new Exception("Invalid Token");
        }
    }

    public static ClaimsPrincipal ValidateToken(String token, PTokenValidationParmeters validationParmeters) {
        var tokenWrapper = ReadToken(token);
        ValidateSignature(tokenWrapper, validationParmeters);

        var now = validationParmeters.GetNow();
        if (tokenWrapper.Token.ValidFrom.ToDateTimeOffset() > now || tokenWrapper.Token.ExpireAt.ToDateTimeOffset() < now) {
            throw new Exception("Token not valid or expired.");
        }

        var claims = new List<Claim> {
            new Claim(ClaimTypes.NameIdentifier, new Guid(tokenWrapper.Token.Subject.ToArray()).ToString()),
            new Claim(ClaimTypes.Name, tokenWrapper.Token.DisplayName),
        };
        foreach (var role in tokenWrapper.Token.Roles) {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        return new ClaimsPrincipal(
            new ClaimsIdentity(claims, nameof(PTokenHandler), ClaimTypes.Name, ClaimTypes.Role)
        );
    }

    public static String CreateToken(PTokenDescriptor descriptor) {
        var token = new PToken() {
            Subject = ByteString.CopyFrom(descriptor.SubjectId.ToByteArray()),
            DisplayName = descriptor.DisplayName,
            ExpireAt = Timestamp.FromDateTimeOffset(descriptor.ExpireAt),
            ValidFrom = Timestamp.FromDateTimeOffset(descriptor.ValidFrom),
            Roles = { descriptor.Roles },
        };

        using var stream = new MemoryStream();
        token.WriteTo(stream);

        stream.Position = 0;
        using var ecdsa = ECDsa.Create(descriptor.PrivateKey.Curve);
        ecdsa.ImportECPrivateKey(descriptor.PrivateKey.PrivateKey, out _);
        var signature = ecdsa.SignData(stream, descriptor.PrivateKey.HashAlgorithm);

        return $"{descriptor.PrivateKey.KeyId}:{Convert.ToBase64String(signature)}:{Convert.ToBase64String(stream.ToArray())}";
    }
}
