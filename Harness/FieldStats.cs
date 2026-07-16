using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace MapleShark2.Harness {
    /// <summary>
    /// Per-field value statistics for one (source, opcode, direction, field) — Phase 1b groundwork.
    ///
    /// Numeric reads (Add&lt;T&gt;, booleans included as width-1 numerics) track n/min/max/sum plus a
    /// distinct-value histogram capped at 64 values; byte blobs (AddField) track n and length min/max/mean.
    /// The classifier decides later what constitutes a violation — this only records.
    /// </summary>
    public sealed class FieldAgg {
        public bool IsBlob;
        public long N;
        public double Min;
        public double Max;
        public double Sum;
        public Dictionary<string, long> Values; // numeric only; capped at 64 distinct + "~other"

        public void AddNumeric(double value, string rendered) {
            if (N == 0) {
                Min = Max = value;
            } else {
                if (value < Min) Min = value;
                if (value > Max) Max = value;
            }

            Sum += value;
            N++;

            Values ??= new Dictionary<string, long>();
            string key = rendered ?? "";
            if (!Values.ContainsKey(key) && Values.Count >= 64) key = "~other";
            Values.TryGetValue(key, out long c);
            Values[key] = c + 1;
        }

        public void AddBlob(int length) {
            IsBlob = true;
            if (N == 0) {
                Min = Max = length;
            } else {
                if (length < Min) Min = length;
                if (length > Max) Max = length;
            }

            Sum += length;
            N++;
        }
    }

    /// <summary>
    /// Aggregates <see cref="FieldAgg"/> keyed by (source build, opcode, direction) -> field key. The
    /// inner dictionary is handed to the sink per packet via <see cref="ParseSink.SetFieldContext"/>, so a
    /// read only pays for one key-string lookup. Absent the --fields flag this object is never created.
    /// </summary>
    public sealed class FieldStatsCollector {
        private readonly uint target;
        private readonly Dictionary<(uint Source, ushort Opcode, bool Outbound), Dictionary<string, FieldAgg>> byCtx =
            new Dictionary<(uint, ushort, bool), Dictionary<string, FieldAgg>>();

        public FieldStatsCollector(uint target) {
            this.target = target;
        }

        public Dictionary<string, FieldAgg> For(uint source, ushort opcode, bool outbound) {
            var key = (source, opcode, outbound);
            if (!byCtx.TryGetValue(key, out Dictionary<string, FieldAgg> fields)) {
                byCtx[key] = fields = new Dictionary<string, FieldAgg>();
            }

            return fields;
        }

        public long FieldCount => byCtx.Values.Sum(d => (long) d.Count);

        public string ToCsv() {
            var sb = new StringBuilder();
            sb.AppendLine("source_build,target_build,opcode,direction,field_key,kind,n,min,max,mean,values");
            foreach (KeyValuePair<(uint Source, ushort Opcode, bool Outbound), Dictionary<string, FieldAgg>> ctx in
                     byCtx.OrderBy(e => e.Key.Opcode).ThenBy(e => e.Key.Outbound).ThenBy(e => e.Key.Source)) {
                (uint source, ushort opcode, bool outbound) = ctx.Key;
                foreach (KeyValuePair<string, FieldAgg> fe in ctx.Value.OrderBy(e => e.Key, StringComparer.Ordinal)) {
                    FieldAgg a = fe.Value;
                    double mean = a.N == 0 ? 0 : a.Sum / a.N;
                    sb.AppendLine(string.Join(",", new[] {
                        source.ToString(CultureInfo.InvariantCulture), target.ToString(CultureInfo.InvariantCulture),
                        $"0x{opcode:X4}", outbound ? "OUT" : "IN",
                        SanitizeKey(fe.Key), a.IsBlob ? "blob" : "num",
                        a.N.ToString(CultureInfo.InvariantCulture),
                        a.Min.ToString(CultureInfo.InvariantCulture), a.Max.ToString(CultureInfo.InvariantCulture),
                        mean.ToString("F3", CultureInfo.InvariantCulture),
                        a.IsBlob ? "-" : EncodeValues(a.Values),
                    }));
                }
            }

            return sb.ToString();
        }

        /// <summary>Sparse "v:count|v:count", most frequent first. "-" when empty.</summary>
        private static string EncodeValues(Dictionary<string, long> values) {
            if (values == null || values.Count == 0) return "-";
            return string.Join("|", values
                .OrderByDescending(e => e.Value)
                .ThenBy(e => e.Key, StringComparer.Ordinal)
                .Select(e => SanitizeValue(e.Key) + ":" + e.Value.ToString(CultureInfo.InvariantCulture)));
        }

        // The field key legitimately carries ':' (label:type) — keep it; only strip CSV/encoding separators.
        private static string SanitizeKey(string s) =>
            s.Replace(',', ';').Replace('|', ';').Replace('\r', ';').Replace('\n', ';');

        private static string SanitizeValue(string s) =>
            s.Replace(',', ';').Replace('|', ';').Replace(':', ';').Replace('\r', ';').Replace('\n', ';');
    }
}
