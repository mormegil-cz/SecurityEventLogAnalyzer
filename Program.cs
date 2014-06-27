using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SecurityEventLogAnalyzer
{
    class Program
    {
        static void Main(string[] args)
        {
            var dict = new Dictionary<Entry, Values>();
            var cnt = 0;
            using (var eventLog = new EventLog("Security"))
            {
                foreach (EventLogEntry entry in eventLog.Entries)
                {
                    string username = null;
                    string domain = null;
                    string machine = null;
                    bool found = false;
                    bool success = false;
                    switch (entry.InstanceId)
                    {
                        case 4624:
                            username = entry.ReplacementStrings[5];
                            domain = entry.ReplacementStrings[6];
                            machine = entry.ReplacementStrings[18];
                            success = true;
                            found = true;
                            break;
                        case 4625:
                            username = entry.ReplacementStrings[5];
                            domain = entry.ReplacementStrings[6];
                            machine = entry.ReplacementStrings[19];
                            success = false;
                            found = true;
                            //Console.WriteLine(entry.Message);
                            //var i = 0;
                            //foreach (var str in entry.ReplacementStrings)
                            //{
                            //    Console.WriteLine("{0}: '{1}'", i++, str);
                            //}
                            //return;
                            break;
                    }

                    if (found)
                    {
                        var port = entry.ReplacementStrings[19];
                        var dictEntry = new Entry { Username = String.Format("{0}\\{1}", domain, username), Machine = machine, Success = success };
                        Values value;
                        if (!dict.TryGetValue(dictEntry, out value))
                        {
                            value = new Values { MinDate = entry.TimeGenerated, MaxDate = entry.TimeGenerated, Count = 1 };
                        }
                        else
                        {
                            value.MaxDate = entry.TimeGenerated;
                            ++value.Count;
                        }
                        dict[dictEntry] = value;
                    }
                }
            }

            foreach (var item in dict)
            {
                var entry = item.Key;
                var value = item.Value;
                Console.WriteLine("{4};{6};{0};{1};{5};{2};{3}", entry.Username, entry.Machine, value.MinDate, value.MaxDate, entry.Success ? "Successful" : "Failed", ResolveIP(entry.Machine), value.Count);
            }
        }

        private static readonly Dictionary<string, string> dnsCache = new Dictionary<string, string>();

        private static string ResolveIP(string ip)
        {
            if (ip == "-") return "";
            string cached;
            if (dnsCache.TryGetValue(ip, out cached)) return cached;
            try
            {
                IPAddress addr;
                if (!IPAddress.TryParse(ip, out addr) || addr.Equals(IPAddress.Any) || addr.Equals(IPAddress.IPv6Any))
                {
                    dnsCache.Add(ip, "");
                    return "";
                }
                var info = Dns.GetHostEntry(addr);
                dnsCache.Add(ip, info.HostName);
                return info.HostName;
            }
            catch (SocketException)
            {
                dnsCache.Add(ip, "");
                return "";
            }
        }

        private class Entry
        {
            public string Username { get; set; }
            public string Machine { get; set; }
            public bool Success { get; set; }

            public override int GetHashCode()
            {
                return (Username ?? "").GetHashCode() ^ (Machine ?? "").GetHashCode() ^ (Success ? 0x45957845 : 0);
            }

            public override bool Equals(object obj)
            {
                var other = obj as Entry;
                if (other == null) return false;
                return other.Username == Username && other.Machine == Machine && other.Success == Success;
            }
        }

        private class Values
        {
            public DateTime MinDate { get; set; }
            public DateTime MaxDate { get; set; }
            public int Count { get; set; }
        }
    }
}
