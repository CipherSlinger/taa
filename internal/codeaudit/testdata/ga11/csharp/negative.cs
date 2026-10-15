// Near-miss negative sample for the C# GA-11 pack.
//
// TestGA11PacksMatchTheirSamples requires this file to produce zero findings.
// The pure math helper it replaces never called any API the pack watches, so it
// passed for the wrong reason: deleting a rule's predicate - leaving the bare
// sink call behind - would not have been noticed, because the call was missing
// too. This file instead calls, for every family that has a predicate, the same
// sink the positive sample calls, with an argument chosen to fail that one
// predicate; remove the predicate and the line starts matching. The calls and
// what their benign arguments deliberately fail:
//
//   FIL_001  File.ReadAllText("config/service.json"), plus the three
//            Path.Combine(..., "summary.bin") calls for the rule's second
//            branch. The literal and the base fail the sensitive-path
//            alternation (.ssh, .env, password, credential, .aws, .kube,
//            id_rsa, authorized_keys, .netrc): an ordinary settings path.
//   ENV_001  Environment.GetEnvironmentVariable("LOG_LEVEL")
//            Fails the sensitive-key alternation (secret, token, api_key,
//            password, credential, auth, session, aws, github, ...): a log
//            level is not a secret.
//   PER_001  Registry.CurrentUser.OpenSubKey(@"Software\Contoso\Service", false)
//            Fails the \Run / /Run predicate that holds the rule to autorun keys.
//   EMB_001  File.WriteAllBytes(destination, snapshot)
//            $DATA binds `snapshot`, which fails the dataset-name regex.
//   EMB_002  File.Copy(templatePath, backup)
//            $DST binds `backup`, which fails the output|export|result
//            alternation.
//   EMB_003  Console.WriteLine(summary)
//            $ARG binds `summary`, which fails the dataset-name regex.
//   EMB_004  A `weights` artefact with no codec word sharing its line, so no
//            branch's two-token conjunction holds.
//
// The remaining six families have no argument predicate at all: their rule
// matches the bare sink call with any argument, so any sink written here would
// fire and make the negative non-empty. They are absent rather than silent -
// CMD_001, NET_001, NET_002, DYN_001, OBF_001, and EXF_001, whose sinks are
// also predicate-free members of NET_001's sink set.

using System;
using System.IO;
using Microsoft.Win32;

namespace Example
{
    // Files a per-run summary beside the operator's template copy and reads the
    // settings document the service was started with.  Ordinary file, registry
    // and console work: no credential store, no network endpoint, no process
    // table.
    public class ReportService
    {
        private readonly string root;

        public ReportService(string root)
        {
            this.root = root;
        }

        // FIL_001 near-miss: the same sink as the positive sample, on a path
        // that names no credential store.
        public string LoadSettings()
        {
            return File.ReadAllText("config/service.json");
        }

        // ENV_001 near-miss: the same sink, on a variable name that is not a
        // secret.
        public string LogLevel()
        {
            return Environment.GetEnvironmentVariable("LOG_LEVEL");
        }

        // PER_001 near-miss: the registry read the text mirror cannot see, on a
        // key with no autorun component.
        public object ReadPreferences()
        {
            return Registry.CurrentUser.OpenSubKey(@"Software\Contoso\Service", false);
        }

        public void Archive(byte[] snapshot)
        {
            string templatePath = Path.Combine(root, "templates", "summary.bin");
            string destination = Path.Combine(root, "archive", "summary.bin");

            // EMB_001 near-miss: a file write whose payload is named
            // `snapshot`, not a dataset.
            File.WriteAllBytes(destination, snapshot);

            // EMB_002 near-miss: a file copy whose destination is named
            // `backup`, not an export directory.
            string backup = Path.Combine(root, "backup", "summary.bin");
            File.Copy(templatePath, backup);

            // EMB_003 near-miss: a console write whose argument is a summary,
            // not sample data.
            string summary = Describe(snapshot.Length);
            Console.WriteLine(summary);
        }

        // EMB_004 near-miss: the artefact this family keys on, used the way a
        // training script uses it - scaled and written - with no encoder and no
        // save word sharing any of these lines.
        public double[] Normalize(double[] weights)
        {
            double total = Sum(weights);
            double[] scaled = new double[weights.Length];
            for (int i = 0; i < weights.Length; i++)
            {
                scaled[i] = total == 0.0 ? 0.0 : weights[i] / total;
            }
            return scaled;
        }

        public void SaveSummary(double[] weights, string path)
        {
            File.WriteAllText(path, string.Format("total={0:0.###}", Sum(weights)));
        }

        private static double Sum(double[] weights)
        {
            double total = 0.0;
            foreach (double w in weights)
            {
                total += w;
            }
            return total;
        }

        private static string Describe(int count)
        {
            return string.Format("summary of {0} bytes", count);
        }
    }
}
