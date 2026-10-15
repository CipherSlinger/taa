package com.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.logging.Logger;

// Negative sample for the Java GA-11 rule pack. This file must produce zero
// findings, and it is written as a hard negative: not benign code the pack
// happens not to look at, but a near miss on every family the pack can
// actually narrow. Each method below calls the same API, in the same sink
// shape, that positive.java calls for one family, and hands it an argument
// chosen to fail the single predicate that rule adds. Delete that predicate
// and this file starts matching, which is the regression
// TestGA11PacksMatchTheirSamples exists to catch. A negative that never
// touched these APIs would stay green through that same edit.
//
// Five of the pack's thirteen families cannot be represented here: their rule
// matches the bare sink with no predicate at all, so every argument satisfies
// it and there is no benign call to write. They are taa-cmd-exec-java,
// taa-net-general-java, taa-net-socket-java, taa-dyn-eval-java and
// taa-obf-exec-java; models/audit/semgrep/rules/java/rules.yaml carries the
// exact pattern lines for each. The hook arm of taa-per-backdoor-java is the
// same case inside a family that otherwise does narrow:
// Runtime.getRuntime().addShutdownHook(...) carries no predicate, so it is
// left out and only that family's file-writing shape appears below.

public class ArtifactService {
    private final Path workDir;
    private final Path logDir;

    public ArtifactService(Path workDir, Path logDir) {
        this.workDir = workDir;
        this.logDir = logDir;
    }

    // fil-probe (taa-fil-probe-java) near miss. Files.readString is the
    // covered sink and the path is built at runtime rather than written as a
    // literal, but it names an ordinary application log: no .ssh, .env,
    // password, credential, .aws, .kube, id_rsa or .netrc substring appears,
    // so the path regex the rule imposes on $PATH is not satisfied.
    public String readRecentLog() throws IOException {
        return Files.readString(logDir.resolve("application.log"));
    }

    // The literal-argument arm of the same family: FileInputStream on a path
    // that carries no credential name either.
    public InputStream openAccessLog() throws IOException {
        return new FileInputStream("/var/log/artifact-service/access.log");
    }

    // env-secret (taa-env-secret-java) near miss. System.getenv is the covered
    // call; HOME carries no secret, token, key, password, credential or
    // session word, so the name regex the rule imposes on $KEY is not
    // satisfied.
    public String homeDir() {
        return System.getenv("HOME");
    }

    // The same sink with a second benign key.
    public String locale() {
        return System.getenv("LANG");
    }

    // emb-data-dump (taa-emb-data-dump-java) near miss. Files.write($PATH,
    // $DATA) is the covered sink; $DATA is an ordinary record buffer, so the
    // payload-name regex the rule imposes on $DATA is not satisfied.
    public void writeArtifact(byte[] record) throws IOException {
        Files.write(workDir.resolve("artifact.bin"), record);
    }

    // emb-copy-export (taa-emb-copy-export-java) near miss. Files.copy($SRC,
    // $DST) is the covered sink; the destination stays inside the work
    // directory and names none of output, export or result, so the
    // destination regex the rule imposes on $DST is not satisfied.
    public void snapshot(Path source) throws IOException {
        Files.copy(source, workDir.resolve("snapshot.bin"));
    }

    // emb-log-dump (taa-emb-log-dump-java) near miss. System.out.println($ARG)
    // is the covered sink; the argument is a short status line, so the
    // data-name regex the rule imposes on $ARG is not satisfied.
    public void report(int processed) {
        System.out.println("processed=" + processed);
    }

    // The logger arm of the same family: $LOG.info($ARG) is the covered sink,
    // and the message names a row count rather than a data set.
    public void logRun(Logger log, int rows) {
        log.info("rows=" + rows);
    }

    // emb-stego-weight (taa-emb-stego-weight-java) near miss. A base64 encode
    // is the shape the family watches, but the encoded value is a thumbnail
    // and the line names neither a weight nor a save, so the keyword pairs its
    // regex arms require are absent.
    public String encodeThumbnail(byte[] thumbnail) {
        return Base64.getEncoder().encodeToString(thumbnail);
    }

    // per-backdoor (taa-per-backdoor-java) near miss. Paths.get building a
    // Path out of a system property, then Files.writeString into it, is the
    // shape the family's regex arms watch; the name written is an application
    // settings file holding none of the profile, cron or systemd markers
    // those arms require.
    public void writeStartupConfig(String value) throws IOException {
        Path settings = Paths.get(System.getProperty("user.home"), "app-settings.conf");
        Files.writeString(settings, value);
    }

    // secret-exfiltration (taa-secret-exfiltration-java) near miss. The write
    // sink $OUT.write($DATA) is present, but $DATA is a caller-supplied
    // summary that never passes through one of the rule's sources - no
    // environment read, no system property, no file read - so the
    // source-to-sink taint predicate is not satisfied.
    public void appendSummary(OutputStream out, String summary) throws IOException {
        out.write(summary.getBytes());
    }
}
