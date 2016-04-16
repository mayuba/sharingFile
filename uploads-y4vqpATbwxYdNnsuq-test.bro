@load base/frameworks/files
global file_count = 0;
global file_count_per_host_per_type: table[addr] of table[string] of count;
event file_state_remove(f: fa_file)
{
local hosts: set[addr];
local mime: string;
local file_count_for_given_host_per_type:table[string] of count;
hosts = f$info$tx_hosts;
local first_three_bytes = f$bof_buffer[0:3];

if ( f?$mime_type )
{
mime = f$mime_type;
}
else
{
if ( f?$bof_buffer )
{

if (first_three_bytes == "ZWS")
{
mime = "application/x-shockwave-flash";
}
else
{
print fmt("Unknown type for magic bytes: %s", first_three_bytes);
mime = "other";
}
}
else
{
mime = "other";
}
}

for ( host in hosts )
{
if( host in file_count_per_host_per_type )
{
file_count_for_given_host_per_type = file_count_per_host_per_type[host];
}
if( mime in file_count_for_given_host_per_type )
{
++file_count_for_given_host_per_type[mime];
}
else
{
file_count_for_given_host_per_type[mime] = 1;
}
file_count_per_host_per_type[host] = file_count_for_given_host_per_type;
}
++file_count;
  if ( mime == "application/java-archive" || mime == "application/x-dosexec")
{
print fmt("moment telechargement : %s", f$last_active);
}
}

event bro_done()
{
local suspicious_mime_types: set[string] = {"application/java-archive", "application/x-dosexec"};
local suspicious_mime_types_for_host: set[string];
print fmt("Total number of files served: %d ", file_count);

for ( host in file_count_per_host_per_type )
{
print fmt("Host: %s ", host);
for ( mime in suspicious_mime_types_for_host)
{
delete suspicious_mime_types_for_host[mime];
}
for ( mime in file_count_per_host_per_type[host] )
{
print fmt(" %s : %d ", mime, file_count_per_host_per_type[host][mime]);
if( mime in suspicious_mime_types )
{
add suspicious_mime_types_for_host[mime];
}
}
if( |suspicious_mime_types_for_host| >= 2 )
{
print fmt("ALERT! Host: %s is potentially serving an exploit kit as it serves files of more suspisious type,namely ", host);
for ( mime in suspicious_mime_types_for_host )
{
print fmt(" %s", mime);
}
}
}
}
