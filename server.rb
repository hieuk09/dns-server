# frozen_string_literal: true

require 'socket'
require_relative 'dns_message'
require_relative 'dns_response'

class Server
  DEFAULT_PORT = 53
  DEFAULT_BIND_ADDRESS = '0.0.0.0'
  DEFAULT_PACKET_SIZE = 1024
  DEFAULT_DNS_SERVER = '1.1.1.1' # Google's public DNS server

  def initialize(port: DEFAULT_PORT, host: DEFAULT_BIND_ADDRESS)
    @socket = UDPSocket.new
    @socket.bind(host, port)
    @cache = {}
  end

  def run
    loop do
      message, addr = @socket.recvfrom(DEFAULT_PACKET_SIZE)
      puts "Received message from #{addr.inspect}"

      dns_message = DNSMessage.new(message)
      response = build_response(dns_message)
      @socket.send(response, 0, addr[3], addr[1])
    end
  end

  private

  def build_response(dns_message)
    qname = dns_message.qname
    dns_response = @cache[qname]

    unless dns_response
      # If not in cache, query another DNS server
      dns_server = DEFAULT_DNS_SERVER
      dns_port = 53
      socket = UDPSocket.new
      socket.connect(dns_server, dns_port)
      socket.send(dns_message.message, 0)
      response, = socket.recvfrom(DEFAULT_PACKET_SIZE)
      socket.close

      # Parse the response and store it in the cache
      dns_response = DNSResponse.new(response)
      @cache[qname] = dns_response
    end

    dns_response.to_response(dns_message)
  end
end

Server.new.run
