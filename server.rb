require 'socket'
require_relative 'dns_message'
require_relative 'dns_response'

class Server
  def initialize(port: 53)
    @socket = UDPSocket.new
    @socket.bind('0.0.0.0', port)
    @cache = {}
  end

  def run
    loop do
      message, addr = @socket.recvfrom(1024)
      puts "Received message from #{addr.inspect}"

      parsed_data = DNSMessage.new(message).to_hash

      response = build_response(parsed_data)
      @socket.send(response, 0, addr[3], addr[1])
    end
  end

  private

  def build_response(parsed_data)
    qname = parsed_data[:queries][0][:qname]
    cached_response = @cache[qname]

    unless cached_response
      # If not in cache, query another DNS server
      dns_server = '8.8.8.8' # Google's public DNS server
      dns_port = 53
      socket = UDPSocket.new
      socket.connect(dns_server, dns_port)
      socket.send(parsed_data[:original_message], 0)
      response, = socket.recvfrom(1024)
      socket.close

      # Parse the response and store it in the cache
      parsed_response = DNSResponse.new(response).to_hash
      cached_response = parsed_response
      @cache[qname] = cached_response
    end

    # Use the cached response to build the final response
    transaction_id = [parsed_data[:transaction_id]].pack('n')
    flags = [0x8180].pack('n') # Standard query response, no error
    questions = [parsed_data[:questions]].pack('n')
    answer_rrs = [1].pack('n') # One answer
    authority_rrs = [0].pack('n')
    additional_rrs = [0].pack('n')

    qname_encoded = qname.split('.').map { |part| [part.length].pack('C') + part }.join + "\0"
    qtype = [parsed_data[:queries][0][:qtype]].pack('n')
    qclass = [parsed_data[:queries][0][:qclass]].pack('n')

    answer_type = qtype
    answer_class = qclass
    answer_name = [cached_response[:answers][0][:name]].pack('n')
    ttl = [cached_response[:answers][0][:ttl]].pack('N')
    rdlength = [4].pack('n') # Length of the RDATA field
    rdata = cached_response[:answers][0][:rdata] # Extract the IP address from the cached response

    transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname_encoded + qtype + qclass + answer_name + answer_type + answer_class + ttl + rdlength + rdata
  end
end

Server.new.run
