# ----------- ACL DKIM ----------------------------------------------
acl_check_dkim:

# Ivo Truxa 2017-01-11
# logwrites mostly for testing and debugging purposes, enable/disable them when needed
#
# ---- IMPORTANT !!!! ----
# In the gkobal settings, you have to enable the DKIM ACL for all senders!
# For example with the following directive:
#
# dkim_verify_signers = $sender_address_domain
#
# Also, do not forget disabling the dkim control for authorized and trusted users 
# and relays. Have a look ad Exim's documentation for details and examples
#
# The settings below use two domain lists: dkim_domains and local_domains.
# The first list contains well known and/or frequently used global domains
# known to be using DKIM. The second list contains all local domain names
# served by our mail server, while we know we use and enforce DKIM at all of 
# them. Checking both lists before doing DNS lookups of policies, saves
# some processing time and bandwidth.


  # Just setting a frequently used debugging logwrite text
  warn  set acl_m_dklog = $dkim_verify_status, D=$sender_address_domain, SG=$dkim_domain, KT=$dkim_key_testing, SUB=$dkim_key_nosubdomains, S=$dkim_selector, R=$dkim_verify_reason

  # We accept failed signatures too, when DKIM is set to the test mode in sender's DNS
  accept condition      = $dkim_key_testing
        add_header      = X-DKIM: TEST mode result for $sender_address_domain (signer=$dkim_cur_signer): $dkim_verify_status; $dkim_verify_reason
#       logwrite        = DKIM DEBUG 01: TEST ERR=$acl_m_dklog

  # Accept valid/passed signatures
  accept dkim_status    = pass
        add_header      = X-DKIM: $dkim_verify_status (address=$sender_address domain=$dkim_cur_signer), signature is good.
#       logwrite        = DKIM DEBUG 02: OK=$acl_m_dklog

  # Deny failures (logging only, while testing; enable later by uncommenting 'deny' and removing the verb 'warn')
  # excluding Gmail/Google while investigating - some email fail
  deny  message         = DKIM test failed: $dkim_verify_reason. Please use only authorized email address & SMTP server!
        dkim_status     = fail
        !sender_domains = gmail.com:google.com
        add_header      = X-DKIM: $dkim_cur_signer ($dkim_verify_status); $dkim_verify_reason
#       logwrite        = DKIM DEBUG 10: RJCT ERR=$acl_m_dklog

  warn  dkim_status     = fail
        sender_domains  = gmail.com:google.com
#       logwrite        = DKIM DEBUG 20: WARN ERR=$acl_m_dklog

  # Deny invalid signatures
  deny  message         = DKIM signature could not be verified: $dkim_verify_reason. Please review the DNS records of $sender_address_domain
        dkim_status     = invalid
        add_header      = X-DKIM: $dkim_cur_signer ($dkim_verify_status); $dkim_verify_reason
#       logwrite        = DKIM DEBUG 11: RJCT ERR=$acl_m_dklog

  # Deny missing signatures at important known signers, frequently used domains,
  # and at local domains (except of someexception.com etc.!)
  # (by doing so here, we save some excess processing time and bandwidth
  #  needed for frequent DNS TXT lookups in the next section)
  deny  message         = DKIM signature missing! The policy of $sender_address_domain enforces the use of DKIM signatures.
        dkim_status     = none
        sender_domains  = +dkim_domains : +local_domains
        !sender_domains = someexception.com : another.exception.org : more.exceptions.com
        add_header      = X-DKIM: $sender_address: signature is missing.
#       logwrite        = DKIM DEBUG 12: RJCT ERR=$acl_m_dklog

# Queying the DNS for signing policies with an external Perl script
# Perl script calls replaced with dnsdb() below
#  deny message         = DKIM signature missing! The policy of $sender_address_domain enforces the use of DKIM signatures.
#       dkim_status     = none
#       !sender_domains = +dkim_domains : +local_domains : someexception.com : another.exception.cz
#       condition       = ${run{/root/scripts/dkim_policy.pl $sender_address_domain}{yes}{no}}
#       logwrite        = DKIM DEBUG 13: RJCT P=$value, D=$sender_address_domain

  # TX 2017-01-11 ----- added polling the DNS for signing policies
  # done in three separate deny blocks to save unnecessary processing
  # querying the DKIM signing policy in _domainkey first (should be used the most)
  # Note: we could/should also exclude domains set into the testing mode ("t=y" in the policy string)
  #   though a big part of domains use "t=y" at perfectly working key, and there must be a signature
  #   anyway, once policy declared. The email lands here only if no DKIM signature was found, hence
  #   excluding testing mode from denying is commented out for now
  deny  message         = DKIM signature missing! The DKIM policy of $sender_address_domain enforces the use of DKIM signatures.
        dkim_status     = none
        set acl_m_dkpl1 = ${lookup dnsdb{txt=_domainkey.$sender_address_domain}}
        condition       = ${if match {$acl_m_dkpl1}{\N(?i).*(o=-|o=!).*\N}}
#       !condition      = ${if match {$acl_m_dkpl1}{\N(?i).*(t=y).*\N}}
#       logwrite        = DKIM DEBUG 51: D=$sender_address_domain, DKIM policy: $acl_m_dkpl1

  # querying the ADSP signing policy in _adsp._domainkey as 2nd (still frequently used)
  # (AFAIK, no test mode defined in ADSP specifications)
  deny  message         = DKIM signature missing! The ADSP policy of $sender_address_domain enforces the use of DKIM signatures.
        dkim_status     = none
        set acl_m_dkpl2 = ${lookup dnsdb{txt=_adsp._domainkey.$sender_address_domain}}
        condition       = ${if match {$acl_m_dkpl2}{\N(?i).*(dkim=all|dkim=discardable).*\N}}
#       logwrite        = DKIM DEBUG 52: D=$sender_address_domain, ADSP policy: $acl_m_dkpl2

  # querying the DomainKeys (RFC4870) policy in _policy._domainkey as last (historical draft)
  deny  message         = DKIM signature missing! The DomainKeys policy of $sender_address_domain enforces the use of DKIM signatures.
        dkim_status     = none
        set acl_m_dkpl3 = ${lookup dnsdb{txt=_policy._domainkey.$sender_address_domain}}
        condition       = ${if match {$acl_m_dkpl3}{\N(?i).*(o=-|o=!).*\N}}
#       !condition      = ${if match {$acl_m_dkpl3}{\N(?i).*(t=y).*\N}}
        logwrite        = DKIM DEBUG 53: D=$sender_address_domain, DK policy: $acl_m_dkpl3

  warn  logwrite        = DKIM DEBUG 59: D=$sender_address_domain, policies DKIM:$acl_m_dkpl1, ADSP:$acl_m_dkpl2, DK:$acl_m_dkpl3
  # ----- / end signing policies check


  # And accept anything else (i.e. senders without DKIM policy, or with a neutral one)
  accept
#       logwrite        = DKIM DEBUG 14: ACPT P=$value, D=$sender_address_domain

# ----------- / end of ACL DKIM -------------------------------------------


