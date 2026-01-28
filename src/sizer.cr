require "./streamer"

class ZipTricks::Sizer
  private class NullIO < IO
    def read(slice : Bytes)
      raise IO::Error.new "Can't read from NullIO"
    end

    def write(slice : Bytes) : Nil
      nil
    end
  end

  def self.size
    streamer = ZipTricks::Streamer.new(NullIO.new)
    sizer = new(streamer)

    yield(sizer)

    streamer.finish
    streamer.bytesize
  end

  def initialize(streamer : ZipTricks::Streamer)
    @streamer = streamer
  end

  # Predeclare an entry with known sizes for size calculation.
  # Use storage_mode: ZipTricks::Streamer::DEFLATED for compressed entries.
  def predeclare_entry(filename : String, uncompressed_size : Int, compressed_size : Int, use_data_descriptor : Bool = false, storage_mode : Int = ZipTricks::Streamer::STORED)
    if storage_mode == ZipTricks::Streamer::DEFLATED
      @streamer.add_deflated_entry(
        filename: filename,
        compressed_size: compressed_size,
        uncompressed_size: uncompressed_size,
        crc32: 0,
        use_data_descriptor: use_data_descriptor)
    else
      @streamer.add_stored_entry(
        filename: filename,
        size: compressed_size,
        crc32: 0,
        use_data_descriptor: use_data_descriptor)
    end
    @streamer.simulate_write(compressed_size)
    if use_data_descriptor
      @streamer.update_last_entry_and_write_data_descriptor(
        crc32: 0,
        compressed_size: compressed_size,
        uncompressed_size: uncompressed_size)
    end
  end
end
