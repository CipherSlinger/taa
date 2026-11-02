package controller

// clonePendingReport deep-copies the map field so the sealed state never shares
// memory with the live outbox entry.
func clonePendingReport(in PendingReportSnapshot) PendingReportSnapshot {
	out := in
	if in.Checksum != nil {
		out.Checksum = make(map[string]any, len(in.Checksum))
		for k, v := range in.Checksum {
			out.Checksum[k] = v
		}
	}
	return out
}