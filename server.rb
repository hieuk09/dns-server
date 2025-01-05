require 'socket'

class DNSParser
  def self.parse(message)
    data = {}
    data[:transaction_id] = message[0..1].unpack1('n') # Unique identifier for the DNS query
    data[:flags] = message[2..3].unpack1('n') # Flags and response codes
    data[:questions] = message[4..5].unpack1('n') # Number of questions in the query
    data[:answer_rrs] = message[6..7].unpack1('n') # Number of answer resource records
    data[:authority_rrs] = message[8..9].unpack1('n') # Number of authority resource records
    data[:additional_rrs] = message[10..11].unpack1('n') # Number of additional resource records

    offset = 12
    data[:queries] = []
    data[:questions].times do
      qname = []
      while (length = message[offset].ord) != 0
        offset += 1
        qname << message[offset, length]
        offset += length
      end
      offset += 1
      qtype = message[offset, 2].unpack1('n') # Type of the query (e.g., A, MX, etc.)
      qclass = message[offset + 2, 2].unpack1('n') # Class of the query (usually IN for internet)
      offset += 4

      data[:queries] << { qname: qname.join('.'), qtype: qtype, qclass: qclass }
    end

    data[:original_message] = message # Add original_message to parsed_data

    data
  end

  def self.parse_response(response)
    data = {}
    data[:transaction_id] = response[0..1].unpack1('n')
    data[:flags] = response[2..3].unpack1('n')
    data[:questions] = response[4..5].unpack1('n')
    data[:answer_rrs] = response[6..7].unpack1('n')
    data[:authority_rrs] = response[8..9].unpack1('n')
    data[:additional_rrs] = response[10..11].unpack1('n')

    offset = 12
    data[:queries] = []
    data[:questions].times do
      qname = []
      while (length = response[offset].ord) != 0
        offset += 1
        qname << response[offset, length]
        offset += length
      end
      offset += 1
      qtype = response[offset, 2].unpack1('n')
      qclass = response[offset + 2, 2].unpack1('n')
      offset += 4

      data[:queries] << { qname: qname.join('.'), qtype: qtype, qclass: qclass }
    end

    data[:answers] = []
    data[:answer_rrs].times do
      name = response[offset, 2].unpack1('n')
      type = response[offset + 2, 2].unpack1('n')
      klass = response[offset + 4, 2].unpack1('n')
      ttl = response[offset + 6, 4].unpack1('N')
      rdlength = response[offset + 10, 2].unpack1('n')
      rdata = response[offset + 12, rdlength]
      offset += 12 + rdlength

      data[:answers] << { name: name, type: type, class: klass, ttl: ttl, rdlength: rdlength, rdata: rdata }
    end

    data
  end
end

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

      parsed_data = DNSParser.parse(message)

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
      response, _ = socket.recvfrom(1024)
      socket.close

      # Parse the response and store it in the cache
      parsed_response = DNSParser.parse_response(response)
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

Server.new().run
