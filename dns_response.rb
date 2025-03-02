class DNSResponse
  DEFAULT_OFFSET = 12

  attr_reader :queries, :answers

  def initialize(response)
    @response = response

    @queries, @answers = parse_response(response)
  end

  def to_hash
    {
      transaction_id:,
      flags:,
      questions:,
      answer_rrs:,
      authority_rrs:,
      additional_rrs:,
      queries:,
      answers:
    }
  end

  def transaction_id
    unpack(0, 1)
  end

  def flags
    unpack(2, 3)
  end

  def questions
    @questions ||= unpack(4, 5)
  end

  def answer_rrs
    unpack(6, 7)
  end

  def authority_rrs
    unpack(8, 9)
  end

  def additional_rrs
    unpack(10, 11)
  end

  def to_response(dns_message)
    qname_encoded = "#{dns_message.qname.split('.').map { |part| [part.length].pack('C') + part }.join}\0"
    answer_type = qtype = [dns_message.qtype].pack('n')
    answer_class = qclass = [dns_message.qclass].pack('n')

    answer_name = [answers[0][:name]].pack('n')
    ttl = [answers[0][:ttl]].pack('N')
    rdlength = [4].pack('n') # Length of the RDATA field
    rdata = answers[0][:rdata] # Extract the IP address from the cached response

    dns_message.raw_transaction_id +
      raw(2, 3) +
      raw(4, 5) +
      raw(6, 7) +
      raw(8, 9) +
      raw(10, 11) +
      qname_encoded +
      qtype +
      qclass +
      answer_name +
      answer_type +
      answer_class +
      ttl +
      rdlength +
      rdata
  end

  private

  def unpack(start, finish)
    raw(start, finish).unpack1('n')
  end

  def raw(start, finish)
    @response[start..finish]
  end

  def parse_response(response)
    offset = DEFAULT_OFFSET

    queries = questions.times.map do
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

      { qname: qname.join('.'), qtype: qtype, qclass: qclass }
    end

    answers = answer_rrs.times.map do
      name = response[offset, 2].unpack1('n')
      type = response[offset + 2, 2].unpack1('n')
      klass = response[offset + 4, 2].unpack1('n')
      ttl = response[offset + 6, 4].unpack1('N')
      rdlength = response[offset + 10, 2].unpack1('n')
      rdata = response[offset + 12, rdlength]
      offset += 12 + rdlength

      { name: name, type: type, class: klass, ttl: ttl, rdlength: rdlength, rdata: rdata }
    end

    [queries, answers]
  end
end
