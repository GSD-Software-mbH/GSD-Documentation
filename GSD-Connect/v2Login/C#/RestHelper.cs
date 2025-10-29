using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using GSD.REST_Lib;
using Newtonsoft.Json.Linq;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace GSD.REST_Lib
{
    public static class RestHelper
    {
        public static void clearSessions()
        {
            restSessions.Clear();
        }

        static Dictionary<string, string> restSessions = new Dictionary<string, string>();

        public static string getSessionToken(string cUrl, string cUserName, string cPassword)
        {
            if (restSessions.ContainsKey(cUserName))
                return restSessions[cUserName];

            JObject jLogin = new JObject();
            jLogin["user"] = cUserName;
            jLogin["pass"] = cPassword;
            jLogin["appNames"] = new JArray(new string[] {  "xyzTestApp" });
            jLogin["device"] = new JObject()
            {
                ["deviceId"] = "xTestDevice_"+ cUserName,
                ["device"] = "xTest Gerät für " + cUserName
            };

            JObject jKey = RestGet(cUrl + "v2/login/key", cUserName, null, null);
            if (jKey == null)
                throw new Exception("no response for login key");
            string encryptKey = (string)jKey["data"]!["key"]!;
            string encryptedRequest = LoginHelperRSA_AES.EncryptRequest(jLogin.ToString(), encryptKey);

            string response = RestPost(cUrl + "v2/login", cUserName, null, null, encryptedRequest);
            JObject jSession = JObject.Parse(response);

            JObject jData = (JObject)jSession["data"];

            if (jData == null)
                throw new Exception(jSession["status"]!["statusMessage"]?.ToString() ?? "unknown error");

            string cSessionToken = (string)jData["sessionId"];

            restSessions[cUserName] = cSessionToken;

            return cSessionToken;
        }

        public static JObject RestGet( string url, string userName, string sessionId, Dictionary<string, string> headers)
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
                using var request = new HttpRequestMessage(HttpMethod.Get, url);

                // feste Header
                request.Headers.Add("appkey", "123");
                if (!string.IsNullOrEmpty(sessionId))
                    request.Headers.Add("sessionId", sessionId);

                // zusätzliche Header
                if (headers != null)
                    foreach (var kv in headers)
                        request.Headers.Add(kv.Key, kv.Value);

                // synchroner Aufruf
                using var response = client
                    .SendAsync(request)
                    .GetAwaiter()
                    .GetResult();

                // nur bei 200 OK parsen
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    string str = response
                        .Content
                        .ReadAsStringAsync()
                        .GetAwaiter()
                        .GetResult();

                    if (str.Contains("\"statusMessage\":\"Session is invalid\"")
                        && !string.IsNullOrEmpty(userName))
                    {
                        restSessions.Remove(userName);
                    }

                    return JObject.Parse(str);
                }
            }
            catch (HttpRequestException httpEx)
            {
                Console.WriteLine($"Error in RestGet: {httpEx.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error in RestGet: {e.Message}");
            }

            return null;
        }

        public static string RestPost(string url, string userName, string? sessionId, Dictionary<string, string>? headers, string postData)
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromMinutes(15) };
                using var request = new HttpRequestMessage(HttpMethod.Post, url)
                {
                    Content = new StringContent(postData, Encoding.UTF8, "application/json")
                };

                // feste Header
                request.Headers.Add("appkey", "123");
                if (!string.IsNullOrEmpty(sessionId))
                    request.Headers.Add("sessionId", sessionId);

                // zusätzliche Header
                if (headers != null)
                    foreach (var header in headers)
                        request.Headers.Add(header.Key, header.Value);

                // synchroner Aufruf
                using var response = client
                    .SendAsync(request)
                    .GetAwaiter()
                    .GetResult();
                string responseString = response
                    .Content
                    .ReadAsStringAsync()
                    .GetAwaiter()
                    .GetResult();

                // Erfolgspfad
                if (response.IsSuccessStatusCode)
                {
                    if (url.EndsWith("v2/login", StringComparison.OrdinalIgnoreCase)
                        && !responseString.StartsWith("{"))
                    {
                        responseString = LoginHelperRSA_AES.DecryptResponse(responseString);
                    }
                    return responseString;
                }
                // Fehlerpfad (HTTP 4xx/5xx)
                else
                {
                    if (url.EndsWith("v2/login", StringComparison.OrdinalIgnoreCase)
                        && !responseString.StartsWith("{"))
                    {
                        responseString = LoginHelperRSA_AES.DecryptResponse(responseString);
                    }
                    if (responseString.Contains("\"statusMessage\":\"Session is invalid\"")
                        && !string.IsNullOrEmpty(userName))
                    {
                        restSessions.Remove(userName);
                    }
                    return responseString;
                }
            }
            catch (HttpRequestException webEx)
            {
                // Netzwerk- oder Timeout-Fehler
                Console.WriteLine($"Error in RestPost: {webEx.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error in RestPost: {e.Message}");
            }

            return null;
        }
    }
}
