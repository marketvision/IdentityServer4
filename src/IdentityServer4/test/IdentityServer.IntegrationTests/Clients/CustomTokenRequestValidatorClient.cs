// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FluentAssertions;
using IdentityModel.Client;
using IdentityServer.IntegrationTests.Clients.Setup;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace IdentityServer.IntegrationTests.Clients
{
    public class CustomTokenRequestValidatorClient
    {
        private const string TokenEndpoint = "https://server/connect/token";

        private readonly HttpClient _client;

        public CustomTokenRequestValidatorClient()
        {
            var val = new TestCustomTokenRequestValidator();
            Startup.CustomTokenRequestValidator = val;

            var builder = new WebHostBuilder()
                .UseStartup<Startup>();
            var server = new TestServer(builder);

            _client = server.CreateClient();
        }

        [Fact]
        public async Task Client_credentials_request_should_contain_custom_response()
        {
            var response = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
            {
                Address = TokenEndpoint,

                ClientId = "client",
                ClientSecret = "secret",
                Scope = "api1"
            });

            var fields = GetFields(response);
            fields["custom"].GetString().Should().Be("custom");
        }

        [Fact]
        public async Task Resource_owner_credentials_request_should_contain_custom_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,

                ClientId = "roclient",
                ClientSecret = "secret",
                Scope = "api1",

                UserName = "bob",
                Password = "bob"
            });

            var fields = GetFields(response);
            fields["custom"].GetString().Should().Be("custom");
        }

        [Fact]
        public async Task Refreshing_a_token_should_contain_custom_response()
        {
            var response = await _client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = TokenEndpoint,

                ClientId = "roclient",
                ClientSecret = "secret",
                Scope = "api1 offline_access",

                UserName = "bob",
                Password = "bob"
            });

            response = await _client.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = TokenEndpoint,
                ClientId = "roclient",
                ClientSecret = "secret",

                RefreshToken = response.RefreshToken
            });

            var fields = GetFields(response);
            fields["custom"].GetString().Should().Be("custom");
        }

        [Fact]
        public async Task Extension_grant_request_should_contain_custom_response()
        {
            var response = await _client.RequestTokenAsync(new TokenRequest
            {
                Address = TokenEndpoint,
                GrantType = "custom",

                ClientId = "client.custom",
                ClientSecret = "secret",

                Parameters =
                {
                    { "scope", "api1" },
                    { "custom_credential", "custom credential"}
                }
            });

            var fields = GetFields(response);
            fields["custom"].GetString().Should().Be("custom");
        }

        private Dictionary<string, JsonElement> GetFields(TokenResponse response)
        {
            return response.Json.ToObject<Dictionary<string, JsonElement>>();
        }
    }
}

namespace IdentityServer.IntegrationTests
{
    public static class JsonElementExtensions
    {
        public static T ToObject<T>(this JsonElement element)
        {
            var json = element.GetRawText();
            return JsonSerializer.Deserialize<T>(json);
        }

        public static T ToObject<T>(this JsonDocument document)
        {
            var json = document.RootElement.GetRawText();
            return JsonSerializer.Deserialize<T>(json);
        }

        public static List<string> ToStringList(this JsonElement element)
        {
            return element.EnumerateArray().Select(item => item.GetString()).ToList();
        }
    }
}