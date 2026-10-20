using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

namespace Acme.Shop.Controllers;

// Benchmark : mêmes fonctionnalités qu'OrdersController.cs, écrites de façon sûre (aucune alerte attendue).
[ApiController]
[Route("api/orders")]
public class OrdersControllerSafe : ControllerBase
{
    private static readonly string[] Formats = { "csv", "pdf" };
    private readonly SqlConnection _db = new(Environment.GetEnvironmentVariable("DB"));
    private static readonly HttpClient Http = new();

    [HttpGet("search")]
    public IActionResult Search(string customer)
    {
        using var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = @customer", _db);
        cmd.Parameters.AddWithValue("@customer", customer);
        return Ok(cmd.ExecuteScalar());
    }

    [HttpGet("export")]
    public IActionResult Export(string format)
    {
        if (!Formats.Contains(format)) return BadRequest();
        var info = new ProcessStartInfo("export.exe") { UseShellExecute = false };
        info.ArgumentList.Add(format);
        Process.Start(info);
        return Ok();
    }

    [HttpGet("invoice")]
    public IActionResult Invoice(string file)
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine("/srv/invoices", Path.GetFileName(file)));
        return File(bytes, "application/pdf");
    }

    [HttpGet("preview")]
    public async Task<IActionResult> Preview(string id)
    {
        var html = await Http.GetStringAsync("https://catalog.example.com/items/" + Uri.EscapeDataString(id));
        return Content(html);
    }

    [HttpPost("import")]
    public async Task<IActionResult> Import()
    {
        var order = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(Request.Body);
        return Ok(order);
    }

    [HttpPost("feed")]
    public IActionResult Feed(string xml)
    {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
        return Ok(doc.DocumentElement?.Name);
    }

    [HttpGet("go")]
    public IActionResult Go(string returnUrl) => LocalRedirect(returnUrl);

    [HttpGet("hello")]
    public ContentResult Hello(string name) => Content("<h1>Bonjour " + HtmlEncoder.Default.Encode(name) + "</h1>", "text/html");

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        return Convert.ToHexString(salt) + ":" + Convert.ToHexString(hash);
    }
}
