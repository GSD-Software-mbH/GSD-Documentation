using GSD.REST_Lib;

Console.WriteLine("Hello, REST!");

try
{
    var token = RestHelper.getSessionToken("http://localhost:8080/df-app/", "TestUser", "Test123klo&%!");
    Console.WriteLine($"session token is {token}");
}
catch (Exception ex)
{
    Console.WriteLine("Error on Login");
    Console.WriteLine(ex.Message);
}
Console.ReadKey();

