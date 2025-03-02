class DNSMessage
  DEFAULT_OFFSET = 12

  attr_reader :message

  def initialize(message)
    @message = message
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
      original_message: @message
    }
  end

  def transaction_id
    unpack(0, 1)
  end

  def raw_transaction_id
    raw(0, 1)
  end

  def flags
    unpack(2, 3)
  end

  def raw_flags
    raw(2, 3)
  end

  def questions
    @questions ||= unpack(4, 5)
  end

  def raw_questions
    raw(4, 5)
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

  def queries
    return @queries if @queries

    offset = DEFAULT_OFFSET

    @queries = questions.times.map do
      qname = []

      while (length = @message[offset].ord) != 0
        offset += 1
        qname << @message[offset, length]
        offset += length
      end

      offset += 1
      qtype = @message[offset, 2].unpack1('n')
      qclass = @message[offset + 2, 2].unpack1('n')
      offset += 4

      { qname: qname.join('.'), qtype: qtype, qclass: qclass }
    end
  end

  def qname
    return if queries.empty?

    queries.first[:qname]
  end

  def qtype
    return if queries.empty?

    queries.first[:qtype]
  end

  def qclass
    return if queries.empty?

    queries.first[:qclass]
  end

  private

  def unpack(start, finish)
    raw(start, finish).unpack1('n')
  end

  def raw(start, finish)
    @message[start..finish]
  end
end
