dkim_policy
===========

#### Query DKIM signing policies of a domain

2016/01/11 NOTE:

### Native Solution for Exim

Although the dkim_policy Perl script is useful for manual testing, and 
has some advantages for the use in Exim, I finally managed to replicate 
very similar functionality with using just native Exim commands (namely
the dnsdb() directive). For most Exim administrators, the native version
of DKIM policy checking is more acceptable. Please find the native 
solution in the file EXIM.conf in this package.

### Perl Script

This script was written to allow better exploiting the possibilities of 
DKIM in Exim.

In the version 4.88 of Exim, available in the time of writing this script,
EXIM supports the DKIM standard for email authentication, which is very
helpful in preventing spam, forgery, and abuse. However, the potential of
DKIM is not fully exploited in Exim, because it only tests DKIM signatures
present in the respective email message. It does not query the DNS at
every sender to try finding out whether the domain owner requires all
messages to be signed or not. It means, in stock Exim (as far as I could
find) you currently cannot reject or quarantine unsigned incoming messages
that are supposed to be signed.

The tool checks if any of the following three policies exists in the
DNS records of given domain and returns the value 0 (success) in such case.
When no signing policy is found, it returns 1 (error).

 - RFC4870(historical) DomainKeys sender signing policies
 - early draft DKIM sender signing policies
 - Author Domain Signing Practices (ADSP)

The Perl script uses the CPAN module Mail::DKIM and its subclasses
Mail::DKIM::Verifier and Mail::DKIM::Policy. It was written in Perl5.24,
using Mail-DKIM-0.40, on a FreeBSD machine. Slight modifications may be
needed on other platforms (for example you may need to adjust the path
to Perl on the first line of the script).

This utility is just a quick intermittent solution allowing the rejection
of unsigned messages. I suppose that later version of Exim will have
such functionality built in. However, the script may be useful also for
other purposes, including quick manual or automated testing of DNS DKIM
settings.

Administrators with busy servers should be aware that calling the script
at every email will add processing time and bandwidth usage for the
additional DNS queries.


Installation:
-------------

Unzip the distribution package and place the dkim_policy.pl to some
location on your server (avoid publicly accessible folders such as the www
tree), and turn on the execution permission bit on the file. On some platforms
you may need to change the path to Perl on the first line of the script. In
doubts about the right path, consult other Perl scripts on your machine.


Required:
- [Perl 5](http://www.perl.org/)
- Perl module [Mail::DKIM](http://search.cpan.org/~jaslong/Mail-DKIM-0.40/lib/Mail/DKIM.pm)
- Perl module [Getopt::Long](http://search.cpan.org/~jv/Getopt-Long-2.49.1/lib/Getopt/Long.pm)

In case the modules are not installed on your system, you can add them in
the following way from command line:
```
 cpan install Mail::DKIM
 cpan install Getopt::Long
```


Examples of use:
----------------

The script prints out the following usage information when invoked with:

`./dkim_policy.pl -h`

```
dkim_policy.pl  DKIM Policy Checker v1.02 (2017-01-10)
  DNS Query of DKIM signing policies (DK/DKIM/ADSP) of a given domain
  Written by Ivo Truxa (c) 2017 <truxa@truxoft.com>

  usage: dkim-policy.pl [options...] FQDN
     Otions:
        -d, --details     display a detailed verbose output
        -c, --changelog   display the version history and exit
        -v, --version     display the version number and exit
        -h, --help        showing this information

     FQDN                 Fully Qualified Domain Name to be tested

  In the default simple mode, the script returns 'all' and the return code 0 (success)
  when any of DK/DKIM/ADSP policies require all messages to be signed. In all other
  cases (no policy defined, or allowing some messages without signatures), the return
  code is 1 (error), and the return string is 'some/undef'. In the detailed mode, the
  script returns DK/DKIM/ADSP policies as found in the DNS.
```

You can use the tool for polling signing policies manually in the following way:

`./dkim_policy.pl -d somedomain.com`

It may be useful also for other purposes, but originally it was written to help 
Exim rejecting unsigned email from domains that declare the use of DKIM on all messages. 
Below, you can find a sample section of an Exim configuration file, demonstrating the 
use of the built-in DKIM function together with the dkim_policy script.

First of all, we have to enable the DKIM ACL for every message, regardless whether 
it is signed or not. We can achieve it with the following global parameter at the 
beginning of the Exim configuration file:

`dkim_verify_signers = $sender_address_domain`

Personally, I only base the reject decision on senders' DKIM, so testing 
$sender_address_domain is all I need. If you want to test all DKIM signatures 
of every message (in case of multiple DKIM's in a message), you need to append 
':$dkim_singers'.

Then, you also need to disable the DKIM control for authorized users, trusted 
relays, and for some other cases, with 'control = dkim_disable_verify'. This 
is well covered in most Exim DKIM Howto's.

The DKIM ACL block below works with some previously defined domain lists. 
Namely the $dkim_domains list (for important well known and often abused 
domains, like those of Gmail, Paypal, many banks, etc.), and $local_domains, 
where I store all domain names served by my server. It is up to you whether 
you populate the list from a flat file with lsearch, use a database, or fill 
them manually.

The configuration section is well commented, so read through it, remove or 
add comments, and adjust it to suit your needs. The use of the dkim_policy 
script is demonstrated at the bottom of the section, where it helps denying 
unsigned messages from senders who's DNS records claim all messages to be 
signed.

In the case the script call fails, the shell returns error (1), and Exim will
process the message as if the policy was undefined (no DKIM enforcement).

```
# ----------- ACL DKIM ----------------------------------------------
acl_check_dkim:
# Ivo Truxa 2017-01-09
# logwrites mostly for testing and debugging purposes, remove later

  # Just setting a frequently used debugging logwrite text
  warn  set acl_m_dklog = $dkim_verify_status, D=$sender_address_domain, SG=$dkim_domain, KT=$dkim_key_testing, SUB=$dkim_key_nosubdomains, S=$dkim_selector, R=$dkim_verify_reason

  # We accept failed signatures too, when DKIM is set to the test mode in sender's DNS
  accept condition      = $dkim_key_testing
        add_header      = X-DKIM: TEST mode result for $sender_address_domain (signer=$dkim_cur_signer): $dkim_verify_status; $dkim_verify_reason
#       logwrite        = DKIM DEBUG 01: TEST=$acl_m_dklog

  # Accept valid/passed signatures
  accept dkim_status    = pass
        add_header      = X-DKIM: $dkim_verify_status (address=$sender_address domain=$dkim_cur_signer), signature is good.
#       logwrite        = DKIM DEBUG 02: OK=$acl_m_dklog

  # Deny failures (logging only, while testing; enable later by uncommenting 'deny' and removing the verb 'warn')
  #deny message         = DKIM test failed: $dkim_verify_reason. Please use only authorized email address & SMTP server!
  warn  dkim_status     = fail
        add_header      = X-DKIM: $dkim_cur_signer ($dkim_verify_status); $dkim_verify_reason
#       logwrite        = DKIM DEBUG 10: ERR=$acl_m_dklog

  # Deny invalid signatures
  #deny message         = DKIM signature could not be verified: $dkim_verify_reason. Please review the DNS records of $sender_address_domain
  # For the moment we are accepting invalid messages (owner's fault, no evidence of a forgery)
  # if denying needed later, uncomment 'deny' above, and remove the 'warn' verb below
  warn  dkim_status     = invalid
        add_header      = X-DKIM: $dkim_cur_signer ($dkim_verify_status); $dkim_verify_reason
#       logwrite        = DKIM DEBUG 11: ERR=$acl_m_dklog

  # Deny missing signatures at important known signers, frequently used domains,
  # and at local domains (except of someexception.com,...)
  # (by doing so here, we save some excess processing time and bandwidth
  #  needed for frequent DNS TXT lookups in the next section)
  deny  message         = DKIM signature missing! The policy of the domain $sender_address_domain enforces DKIM signatures on all email.
        dkim_status     = none
        sender_domains  = +dkim_domains : +local_domains
        !sender_domains = someexception.com : other.exception.org : more.exceptions.com
        add_header      = X-DKIM: $sender_address: signature is missing.
#       logwrite        = DKIM DEBUG 12: ERR=$acl_m_dklog

  # query DNS for the DKIM signing policy, and reject message if signing enforced
  deny  message         = DKIM signature missing! The policy of the domain $sender_address_domain enforces DKIM signatures on all email.
        dkim_status     = none
        !sender_domains = +dkim_domains : +local_domains
        condition       = ${run{/path/to/dkim_policy.pl $sender_address_domain}{yes}{no}}
#       logwrite        = DKIM DEBUG 13: P=$value, D=$sender_address_domain

  # And accept anything else (i.e. senders without DKIM policy, or with a neutral one)
  accept
```


Contact:
--------

You can send your questions or kudos to [Ivo Truxa](mailto:truxa@truxoft.com)

You can also submit issues, or modifications through the
[GitHub repository](https://github.com/truxoft/dkim_policy/)


License:
--------

dkim_ is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.

dkim_policy is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
dkim_policy; if not, write to the Free Software Foundation, Inc., 51 Franklin
Street, Fifth Floor, Boston, MA 02110, USA


