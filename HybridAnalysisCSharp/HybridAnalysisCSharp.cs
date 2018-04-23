using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;

namespace HybridAnalysisCSharp
{
  class HybridAnalysisCSharp
  {
    static void Main(string[] args)
    {
      string apiKey = "";
      string apiKeyFile = "apikey.txt";

      if (File.Exists(apiKeyFile))
      {
        apiKey = File.ReadAllText(apiKeyFile);
        if (apiKey.Length == 0)
        {
          Console.WriteLine("Please populate apikey.txt with your api key.");
          System.Environment.Exit(1);
        }
      }
      else
      {
        Console.WriteLine("Please create apikey.txt in the same dir as the exe with contents being your api key");
        System.Environment.Exit(1);
      }


      if (args.Length > 0)
      {
        string userAgent = "HybridAnalysisCSharp v0.1";
        string apiURI = "https://www.hybrid-analysis.com/api/v2/search/hash";
        string ourHash = args[0];
        string myParams = "hash=" + ourHash;
        string savedResultsStr = "";

        using (WebClient wc = new WebClient())
        {
          Console.WriteLine("\nHASH: " + ourHash);
          wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
          wc.Headers[HttpRequestHeader.UserAgent] = userAgent;
          wc.Headers["api-key"] = apiKey;
          var watch = System.Diagnostics.Stopwatch.StartNew();
          string rawResult = wc.UploadString(apiURI, myParams);
          watch.Stop();
          var elapsedMs = watch.ElapsedMilliseconds;
          //string rawResult = @"[{""job_id"":""5adc7bfd7ca3e11368518a13"",""environment_id"":""100"",""environment_description"":""Windows 7 32 bit"",""size"":250373,""type"":""PE32 executable(GUI) Intel 80386, for MS Windows"",""type_short"":[""peexe""],""target_url"":null,""state"":""SUCCESS"",""submit_name"":""mindful.exe"",""md5"":""20012a3fd4294733fe33d5640e118d35"",""sha1"":""5846023d2b093d23b77abdb5a367141d41e010d7"",""sha256"":""4dadbdb6127e783bee4c2381f2c4daa975d63220a475cdebeeabc78026777a5f"",""sha512"":""e8bdd9d2de272b98f05ef268df1468302e88a8e24950f9538bb92767d1b8e327575a138ed8a36a4b2ce3c2ef224173fbee2113bf4251ce775b3b940f23e0c143"",""ssdeep"":""6144:ED1MW6R8c9u9UriRV3tJgkp7E9sXdVyygk:6M7R8Kor17fdpgk"",""imphash"":""eeda7ed1c8f4a5189c125f0dd1052ae5"",""av_detect"":15,""vx_family"":""QVM10.1.AC95.Malware"",""url_analysis"":false,""analysis_start_time"":""2018-04-22T13:10:43-05:00"",""threat_score"":100,""interesting"":false,""threat_level"":2,""verdict"":""malicious"",""certificates"":[],""domains"":[""ransomware.bit"",""ns2.corp - servers.ru"",""ns1.corp - servers.ru"",""ipv4bot.whatismyipaddress.com""],""classification_tags"":[""ransomware""],""compromised_hosts"":[""66.171.248.178""],""hosts"":[""66.171.248.178"",""89.203.10.56"",""94.249.60.127""],""total_network_connections"":3,""total_processes"":15,""total_signatures"":55,""extracted_files"":[],""processes"":[],""file_metadata"":null}]";
          if (rawResult.Length > 0)
          {
            dynamic responseJson = JsonConvert.DeserializeObject(rawResult);
            savedResultsStr = saveRawJsonToFile(ourHash, responseJson);

            showResults(responseJson);
          }
          Console.WriteLine("\nThe API took " + elapsedMs + " milliseconds to respond");
          Console.WriteLine(savedResultsStr);
        }

      }
      else
      {
        Console.WriteLine("Please provide a hash.");
        System.Environment.Exit(1);
      }
    }

    private static string saveRawJsonToFile(string hash, object json)
    {
      string resultsDir = "results";
      if (!Directory.Exists(resultsDir))
      {
        Directory.CreateDirectory(resultsDir);
      }

      DateTime today = DateTime.Today;
      string todayDirName = today.ToString("yyyy-MM-dd");
      string fullSaveDir = resultsDir + "/" + todayDirName;
      if (!Directory.Exists(fullSaveDir))
      {
        Directory.CreateDirectory(fullSaveDir);
      }

      string saveToFileName = fullSaveDir + "/" + hash + ".json";
      string prettyJson = JsonConvert.SerializeObject(json, Formatting.Indented);
      System.IO.File.WriteAllText(saveToFileName, prettyJson);
      return "Wrote " + prettyJson.Length + " bytes to " + saveToFileName;
    }

    private static void showResults(dynamic responseJson)
    {
      var r = responseJson.First;
      C("Threat Score", r.threat_score);
      C("Verdict", r.verdict);
      C("Family", r.vx_family);
      C("AV Detect", r.av_detect);

      C("\nAnalysis Start Time", r.analysis_start_time);
      C("Submitted Filename", r.submit_name);
      C("Type", r.type);
      C("Size", r.size);

      C("\nmd5", r.md5);
      C("sha1", r.sha1);
      C("sha256", r.sha256);
      C("imphash", r.imphash);
      C("ssdeep", r.ssdeep);

      showNested("Certificates", r.certificates);
      showNested("Classification Tags", r.classification_tags);
      showNested("Domains", r.domains);
      showNested("Compromised Hosts", r.compromised_hosts);
      showNested("Hosts", r.hosts);

      C("\nTotal Network Connections", r.total_network_connections);
      C("Total Processes", r.total_processes);
      C("Total Signatures", r.total_signatures);
    }

    private static void showNested(string name, dynamic obj)
    {
      C("\n" + name, obj.Count);
      if (obj.Count > 0)
      {
        int count = 1;
        foreach (var thing in obj)
        {
          C(count.ToString(), thing, true);
          ++count;
        }
      }
    }

    private static void C(string key, dynamic val, bool shifted = false)
    {
      if (shifted)
      {
        Console.Write("\t");
      }
      Console.WriteLine(key + ": " + val);
    }
  }
}
