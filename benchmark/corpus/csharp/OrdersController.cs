using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Shop.Controllers;

// Benchmark : failles courantes d'une API ASP.NET Core (vulnérable).
[ApiController]
[Route("api/orders")]
public class OrdersController : ControllerBase
{
    private readonly SqlConnection _db = new(Environment.GetEnvironmentVariable("DB"));
    private static readonly HttpClient Http = new();

    [HttpGet("search")]
    public IActionResult Search(string customer)
    {
        var sql = "SELECT * FROM Orders WHERE Customer = '" + customer + "'";
        using var cmd = new SqlCommand(sql, _db);
        return Ok(cmd.ExecuteScalar());
    }

    [HttpGet("export")]
    public IActionResult Export(string format)
    {
        Process.Start("cmd.exe", "/c export.bat " + format);
        return Ok();
    }

    [HttpGet("invoice")]
    public IActionResult Invoice(string file)
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine("/srv/invoices", file));
        return File(bytes, "application/pdf");
    }

    [HttpGet("preview")]
    public async Task<IActionResult> Preview(string url)
    {
        var html = await Http.GetStringAsync(url);
        return Content(html);
    }

    [HttpPost("import")]
    public IActionResult Import()
    {
        var formatter = new BinaryFormatter();
        var order = formatter.Deserialize(Request.Body);
        return Ok(order);
    }

    [HttpPost("feed")]
    public IActionResult Feed(string xml)
    {
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.LoadXml(xml);
        return Ok(doc.DocumentElement?.Name);
    }

    [HttpGet("go")]
    public IActionResult Go(string returnUrl) => Redirect(returnUrl);

    [HttpGet("hello")]
    public ContentResult Hello(string name) => Content("<h1>Bonjour " + name + "</h1>", "text/html");

    public static string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        return Convert.ToHexString(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
    }
}
