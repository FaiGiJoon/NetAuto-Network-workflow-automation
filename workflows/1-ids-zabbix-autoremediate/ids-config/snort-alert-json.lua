-- Add to snort.lua (Snort 3): JSON alerts with the fields alert_watcher.py reads.
alert_json =
{
    file = true,
    limit = 100,
    fields = 'timestamp src_addr src_port dst_addr dst_port proto msg priority sid action',
}
