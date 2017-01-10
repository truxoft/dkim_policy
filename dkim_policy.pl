#!/usr/local/bin/perl
# dkim-policy.pl      License: GPLv2
# Ivo Truxa  (c) 2017  <truxa@truxoft.com>

# ------- VERSION -----------------------------------------------------
my $version = "1.02";
my $verdate = "2017-01-10";

# ------ PURPOSE ------------------------------------------------------
# The purpose of the script is returning of one of the available DKIM
# policies available in DNS records of a given domain (if available).
# This function is currently not availble in the built-in DKIM
# processing in Exim mail server, and it is necessary if rejecting or
# flagging of DKIM-unsigned messages is required. Before rejecting
# an unsigned message, we need to know whether the messages are
# supposed and required to be signed at all.
#
# The tool checks if any of the following three policies exists in the
# DNS records of given domain and returns the value 0 in such case.
# When no signing policy is found, it returns 1.
#  - RFC4870(historical) DomainKeys sender signing policies
#  - early draft DKIM sender signing policies
#  - Author Domain Signing Practices (ADSP)
#
# ---------------------------------------------------------------------

my $u1 = "\ndkim_policy.pl  DKIM Policy Checker v".$version." (".$verdate.")                     \n".
         "  Written by Ivo Truxa (c) 2017 <truxa\@truxoft.com>                                   \n";
my $u2 = "  usage: dkim-policy.pl [options...] FQDN                                              \n".
         "     Otions:                                                                           \n".
         "        -d, --details     display a detailed verbose output instead of a simple result \n".
         "        -c, --changelog   display version history and exit                             \n".
         "        -v, --version     display version number and exit                              \n".
         "        -h, --help        showing this information                                     \n\n".
         "     FQDN                 Fully Qualified Domain Name to be tested                     \n\n".
         "  In the default simple mode, the script returns 0 (success) if any of DK/DKIM/ADSP    \n".
         "  policies requires all messages to be signed. In all other cases (no policy defined,  \n".
         "  or allowing some messages without singatures), the return value is 1 (error).        \n\n".
         "  In the detailed mode, the script returns DK/DKIM/ADSP policies as found in the DNS.  \n";
my $changelog =
"  1.02 [Ivo Truxa] 2017/01/10                                                                   \n".
"       - return code 0 (enforced) or 1 (undefined) kept, but STDOUT prints a verbose result     \n".
"  1.01 [Ivo Truxa] 2017/01/09                                                                   \n".
"       - inversed output - 0: success = DKIM signing enforced                                   \n".
"       -                   1: error = policy undefined or signing not enforced                  \n".
"       - policy loop interrupted at the 1st hit, to save time, processing power, and bandwidth  \n".
"       - full policy loop for detailed verbose mode kept                                        \n".
"       - cosmetic formatting changes, editing of help texts                                     \n".
"  1.00 [Ivo Truxa] 2017/01/08                                                                   \n".
"       - this tool was written on FreeBSD, using Perl module Mail-DKIM-0.40 and Perl5-24        \n".
"       - at this date, it was not tested on other platforms or with other versions of Perl      \n";

use strict;
use warnings;
use Getopt::Long;
use Mail::DKIM::Verifier;
use Mail::DKIM::Policy;

$|=1;

# -----------------------------------------------------------------------
sub myend($) {print shift(),"\n"; exit 1;}
# -----------------------------------------------------------------------
my %opts;
GetOptions( \%opts, 'details', 'version', 'help', 'changelog');
$opts{'help'}      and myend("$u1  \n$u2  \n");
$opts{'changelog'} and myend("$u1  \n$changelog  \n");
$opts{'version'}   and myend("dkim_policy v$version ($verdate)  \n");
# -----------------------------------------------------------------------


my $domain = $ARGV[0];
my $result = 1;

if ($domain)
{
  # FQDN syntax checking of the domain string could be added here

  my $dkim  = Mail::DKIM::Verifier->new();
  # default result is 1 (error / no dkim enforcement)

  # feed a dummy message to the DKIM verifier object
  # passing so the queried domain name in the From field
  $dkim->PRINT("From: dkim\@".$domain."\r\n");
  $dkim->PRINT("To: dkim\@dkim.org\r\n\r\n");

  if ($opts{'details'}) {print $u1."\nDKIM policies for ".$domain.":\n";}

  # get all policies that apply to a verified message
  foreach my $policy ($dkim->policies)
  {
      if ($opts{'details'})
        {print $policy->name() . ": " . $policy->as_string() . "\n";}
      if ($policy->as_string() =~ "o=-")
        {
         $result = 0;
         if (!$opts{'details'}) {last;}
        }
  }
  $dkim->CLOSE;
  if ($opts{'details'})
       {print "\nResult: ";
        print $result ? "DKIM undefined or unenforced\n\n" : "DKIM enforced\n\n";}
  else {print $result ? "some/undef " : "all ";}
}
 else
{
  myend("No domain name given!\n\n$u2");
}

exit $result;
