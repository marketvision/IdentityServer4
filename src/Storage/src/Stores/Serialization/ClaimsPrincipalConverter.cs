// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

#pragma warning disable 1591

namespace IdentityServer4.Stores.Serialization
{
    public class ClaimsPrincipalConverter : JsonConverter<ClaimsPrincipal>
    {
        public override ClaimsPrincipal Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var source = JsonSerializer.Deserialize<ClaimsPrincipalLite>(ref reader, options);
            return source?.ToClaimsPrincipal();
        }

        public override void Write(Utf8JsonWriter writer, ClaimsPrincipal value, JsonSerializerOptions options)
        {
            var target = value.ToClaimsPrincipalLite();
            JsonSerializer.Serialize(writer, target, options);
        }
    }

    public static class ClaimsPrincipalLiteExtensions
    {
        /// <summary>
        /// Converts a ClaimsPrincipalLite to ClaimsPrincipal
        /// </summary>
        public static ClaimsPrincipal ToClaimsPrincipal(this ClaimsPrincipalLite principal)
        {
            var claims = principal.Claims.Select(x => new Claim(x.Type, x.Value, x.ValueType ?? ClaimValueTypes.String)).ToArray();
            var id = new ClaimsIdentity(claims, principal.AuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);

            return new ClaimsPrincipal(id);
        }

        /// <summary>
        /// Converts a ClaimsPrincipal to ClaimsPrincipalLite
        /// </summary>
        public static ClaimsPrincipalLite ToClaimsPrincipalLite(this ClaimsPrincipal principal)
        {
            var claims = principal.Claims.Select(
                    x => new ClaimLite
                    {
                        Type = x.Type,
                        Value = x.Value,
                        ValueType = x.ValueType == ClaimValueTypes.String ? null : x.ValueType
                    }).ToArray();

            return new ClaimsPrincipalLite
            {
                AuthenticationType = principal.Identity!.AuthenticationType!,
                Claims = claims
            };
        }
    }
}
