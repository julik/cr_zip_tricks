require "compress/deflate"

# A very barebones ZIP file reader. Is made for maximum interoperability, but at the same
# time we attempt to keep it somewhat concise.
#
# Please **BEWARE** - using this is a security risk if you are reading files that have been
# supplied by users. This implementation has _not_ been formally verified for correctness. As
# ZIP files contain relative offsets in lots of places it might be possible for a maliciously
# crafted ZIP file to put the decode procedure in an endless loop, make it attempt huge reads
# from the input file and so on. Additionally, the reader module for deflated data has
# no support for ZIP bomb protection. So either limit the `FileReader` usage to the files you
# trust, or triple-check all the inputs upfront.
#
# ## Supported features
#
# * Deflate and stored storage modes
# * Zip64 (extra fields and offsets)
# * Data descriptors
#
# ## Unsupported features
#
# * Archives split over multiple disks/files
# * Any ZIP encryption
# * EFS language flag and InfoZIP filename extra field
# * CRC32 checksums are _not_ verified
#
# ## Mode of operation
#
# By default, `FileReader` _ignores_ the data in local file headers (as it is
# often unreliable). It reads the ZIP file "from the tail", finds the
# end-of-central-directory signatures, then reads the central directory entries,
# reconstitutes the entries with their filenames, attributes and so on, and
# sets these entries up with the absolute _offsets_ into the source file/IO object.
# These offsets can then be used to extract the actual compressed data of
# the files and to expand it.
#
# ## Recovering damaged or incomplete ZIP files
#
# If the ZIP file you are trying to read does not contain the central directory
# records `read_zip_structure` will not work, since it starts the read process
# from the EOCD marker at the end of the central directory and then crawls
# "back" in the IO to figure out the rest. You can explicitly apply a fallback
# for reading the archive "straight ahead" instead using `read_zip_straight_ahead`
# - the method will instead scan your IO from the very start, skipping over
# the actual entry data. This is less efficient than central directory parsing since
# it involves a much larger number of reads (1 read from the IO per entry in the ZIP).
class ZipTricks::FileReader
  class ReadError < Exception
  end

  class UnsupportedFeature < Exception
  end

  class InvalidStructure < ReadError
  end

  class LocalHeaderPending < Exception
    def message
      "The compressed data offset is not available (local header has not been read)"
    end
  end

  class MissingEOCD < Exception
    def message
      "Could not find the EOCD signature in the buffer - maybe a malformed ZIP file"
    end
  end

  private class StoredReader
    def initialize(@io : IO, @compressed_data_size : Int64)
      @already_read = 0_i64
    end

    def extract(n_bytes : Int? = nil) : Bytes?
      n = (n_bytes || (@compressed_data_size - @already_read)).to_i64
      return nil if eof?

      available = @compressed_data_size - @already_read
      return nil if available == 0
      n = available if n > available
      return Bytes.empty if n == 0

      buf = Bytes.new(n)
      bytes_read = @io.read(buf)
      return nil if bytes_read == 0

      @already_read += bytes_read
      buf[0, bytes_read]
    end

    def eof? : Bool
      @already_read >= @compressed_data_size
    end
  end

  private class InflatingReader
    @finished : Bool = false

    def initialize(from_io : IO, compressed_data_size : Int64)
      # Read all compressed data into memory, then inflate from there
      compressed_bytes = Bytes.new(compressed_data_size)
      from_io.read_fully(compressed_bytes)
      compressed_io = IO::Memory.new
      compressed_io.write(compressed_bytes)
      compressed_io.rewind
      @inflater = Compress::Deflate::Reader.new(compressed_io)
    end

    def extract(n_bytes : Int? = nil) : Bytes?
      return nil if @finished
      buf = Bytes.new(n_bytes || 16384)
      bytes_read = @inflater.read(buf)
      if bytes_read == 0
        @finished = true
        return nil
      end
      buf[0, bytes_read]
    end

    def eof? : Bool
      @finished
    end
  end

  # Represents a file within the ZIP archive being read.
  class ZipEntry
    property made_by : UInt16 = 0_u16
    property version_needed_to_extract : UInt16 = 0_u16
    property gp_flags : UInt16 = 0_u16
    property storage_mode : UInt16 = 0_u16
    property dos_time : UInt16 = 0_u16
    property dos_date : UInt16 = 0_u16
    property crc32 : UInt32 = 0_u32
    property compressed_size : UInt64 = 0_u64
    property uncompressed_size : UInt64 = 0_u64
    property filename : String = ""
    property disk_number_start : UInt16 = 0_u16
    property internal_attrs : UInt16 = 0_u16
    property external_attrs : UInt32 = 0_u32
    property local_file_header_offset : UInt64 = 0_u64
    property comment : String = ""

    @compressed_data_offset : UInt64? = nil

    # Returns a reader for the actual compressed data of the entry.
    #
    #   reader = entry.extractor_from(source_file)
    #   outfile.write(reader.extract(512 * 1024).not_nil!) until reader.eof?
    def extractor_from(from_io)
      from_io.seek(compressed_data_offset.to_i64, IO::Seek::Set)
      case storage_mode
      when 8
        InflatingReader.new(from_io, compressed_size.to_i64)
      when 0
        StoredReader.new(from_io, compressed_size.to_i64)
      else
        raise UnsupportedFeature.new("Unsupported storage mode for reading - #{storage_mode}")
      end
    end

    # Returns the offset at which compressed data starts in the IO
    def compressed_data_offset : UInt64
      @compressed_data_offset || raise(LocalHeaderPending.new)
    end

    # Tells whether the compressed data offset is already known for this entry
    def known_offset? : Bool
      !@compressed_data_offset.nil?
    end

    # Tells whether the entry uses a data descriptor (bit 3 in GP flags)
    def uses_data_descriptor? : Bool
      (gp_flags & 0x0008) == 0x0008
    end

    # Sets the offset at which the compressed data for this file starts in the ZIP
    def compressed_data_offset=(offset)
      @compressed_data_offset = offset.to_u64
    end
  end

  # To prevent too many tiny reads, read the maximum possible size of end of
  # central directory record upfront (all the fixed fields + at most 0xFFFF
  # bytes of the archive comment)
  MAX_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE = 4 + # Offset of the start of central directory
    4 + # Size of the central directory
    2 + # Number of files in the cdir
    4 + # End-of-central-directory signature
    2 + # Number of this disk
    2 + # Number of disk with the start of cdir
    2 + # Number of files in the cdir of this disk
    2 + # The comment size
    0xFFFF # Maximum comment size

  # To prevent too many tiny reads, read the maximum possible size of the local file header upfront.
  MAX_LOCAL_HEADER_SIZE = 4 + # signature
    2 + # Version needed to extract
    2 + # gp flags
    2 + # storage mode
    2 + # dos time
    2 + # dos date
    4 + # CRC32
    4 + # Comp size
    4 + # Uncomp size
    2 + # Filename size
    2 + # Extra fields size
    0xFFFF + # Maximum filename size
    0xFFFF # Maximum extra fields size

  SIZE_OF_USABLE_EOCD_RECORD = 4 + # Signature
    2 + # Number of this disk
    2 + # Number of the disk with the EOCD record
    2 + # Number of entries in the central directory of this disk
    2 + # Number of entries in the central directory total
    4 + # Size of the central directory
    4   # Start of the central directory offset

  # Parse an IO handle to a ZIP archive into an array of Entry objects, reading from
  # the end of the IO object (central directory).
  def read_zip_structure(io, read_local_headers : Bool = true) : Array(ZipEntry)
    zip_file_size = io.size.to_i64
    eocd_offset = get_eocd_offset(io, zip_file_size)

    zip64_end_of_cdir_location = get_zip64_eocd_location(io, eocd_offset)
    num_files, cdir_location, _cdir_size =
      if zip64_end_of_cdir_location
        num_files_and_central_directory_offset_zip64(io, zip64_end_of_cdir_location)
      else
        num_files_and_central_directory_offset(io, eocd_offset)
      end

    seek(io, cdir_location)

    # Read the entire central directory AND anything behind it, in one fell swoop.
    # We read the entire "tail" of the ZIP ignoring the central directory size
    # altogether, because in some files the central directory size is misreported.
    remaining = io.size.to_i64 - io.pos.to_i64
    central_directory_bytes = Bytes.new(remaining)
    io.read_fully(central_directory_bytes)
    central_directory_io = IO::Memory.new
    central_directory_io.write(central_directory_bytes)
    central_directory_io.rewind

    entries = (0...num_files).map do |entry_n|
      read_cdir_entry(central_directory_io)
    end

    read_local_headers_for(entries, io) if read_local_headers

    entries
  end

  # Read entries from a ZIP "straight ahead", without using the central directory.
  # Useful for recovering damaged or truncated ZIP files.
  # Does not support data descriptors.
  def read_zip_straight_ahead(io) : Array(ZipEntry)
    entries = [] of ZipEntry
    begin
      while true
        cur_offset = io.pos
        entry = read_local_file_header(io)
        if entry.uses_data_descriptor?
          raise UnsupportedFeature.new(
            "The local file header at #{cur_offset} uses " \
            "a data descriptor and the start of next entry " \
            "cannot be found")
        end
        entries << entry
        next_local_header_offset = entry.compressed_data_offset.to_i64 + entry.compressed_size.to_i64
        seek(io, next_local_header_offset)
      end
    rescue ReadError | OverflowError
    end
    entries
  end

  # Parse the local header entry and get the offset in the IO at which the
  # actual compressed data of the file starts within the ZIP.
  def read_local_file_header(io) : ZipEntry
    local_file_header_offset = io.pos.to_i64

    # Reading in bulk is cheaper - grab the maximum length of the local header
    buf = Bytes.new(MAX_LOCAL_HEADER_SIZE)
    bytes_read = io.read(buf)
    raise ReadError.new("Reached EOF at local file header") if bytes_read == 0

    header_io = IO::Memory.new
    header_io.write(buf[0, bytes_read])
    header_io.rewind

    assert_signature(header_io, 0x04034b50_u32)
    e = ZipEntry.new
    e.version_needed_to_extract = read_2b(header_io)
    e.gp_flags = read_2b(header_io)
    e.storage_mode = read_2b(header_io)
    e.dos_time = read_2b(header_io)
    e.dos_date = read_2b(header_io)
    e.crc32 = read_4b(header_io)
    e.compressed_size = read_4b(header_io).to_u64
    e.uncompressed_size = read_4b(header_io).to_u64

    filename_size = read_2b(header_io)
    extra_size = read_2b(header_io)
    e.filename = String.new(read_n(header_io, filename_size.to_i32))
    extra_fields_bytes = read_n(header_io, extra_size.to_i32)

    # Parse out the extra fields
    extra_table = parse_out_extra_fields(extra_fields_bytes)

    # ...of which we really only need the Zip64 extra
    if zip64_extra_contents = extra_table[0x0001_u16]?
      zip64_extra = IO::Memory.new
      zip64_extra.write(zip64_extra_contents)
      zip64_extra.rewind
      # The order of the fields in the ZIP64 extended information record is fixed,
      # but the fields will only appear if the corresponding Local or Central
      # directory record field is set to 0xFFFF or 0xFFFFFFFF.
      e.uncompressed_size = read_8b(zip64_extra) if e.uncompressed_size == 0xFFFFFFFF_u64
      e.compressed_size = read_8b(zip64_extra) if e.compressed_size == 0xFFFFFFFF_u64
    end

    offset = local_file_header_offset + header_io.pos.to_i64
    e.compressed_data_offset = offset.to_u64

    e
  end

  # Get the compressed data offset for an entry at a given local file header offset
  def get_compressed_data_offset(io, local_file_header_offset : Int) : UInt64
    seek(io, local_file_header_offset)
    entry_recovered = read_local_file_header(io)
    entry_recovered.compressed_data_offset
  end

  # Class method convenience wrappers
  def self.read_zip_structure(io, read_local_headers : Bool = true) : Array(ZipEntry)
    new.read_zip_structure(io, read_local_headers)
  end

  def self.read_zip_straight_ahead(io) : Array(ZipEntry)
    new.read_zip_straight_ahead(io)
  end

  # Read a single central directory entry from the IO. Exposed for testing.
  def read_cdir_entry(io) : ZipEntry
    assert_signature(io, 0x02014b50_u32)
    e = ZipEntry.new
    e.made_by = read_2b(io)
    e.version_needed_to_extract = read_2b(io)
    e.gp_flags = read_2b(io)
    e.storage_mode = read_2b(io)
    e.dos_time = read_2b(io)
    e.dos_date = read_2b(io)
    e.crc32 = read_4b(io)
    e.compressed_size = read_4b(io).to_u64
    e.uncompressed_size = read_4b(io).to_u64
    filename_size = read_2b(io)
    extra_size = read_2b(io)
    comment_len = read_2b(io)
    e.disk_number_start = read_2b(io)
    e.internal_attrs = read_2b(io)
    e.external_attrs = read_4b(io)
    e.local_file_header_offset = read_4b(io).to_u64
    e.filename = String.new(read_n(io, filename_size.to_i32))

    # Extra fields
    extras = read_n(io, extra_size.to_i32)
    # Comment
    e.comment = String.new(read_n(io, comment_len.to_i32))

    # Parse out the extra fields
    extra_table = parse_out_extra_fields(extras)

    # ...of which we really only need the Zip64 extra
    if zip64_extra_contents = extra_table[0x0001_u16]?
      zip64_extra = IO::Memory.new
      zip64_extra.write(zip64_extra_contents)
      zip64_extra.rewind
      e.uncompressed_size = read_8b(zip64_extra) if e.uncompressed_size == 0xFFFFFFFF_u64
      e.compressed_size = read_8b(zip64_extra) if e.compressed_size == 0xFFFFFFFF_u64
      e.local_file_header_offset = read_8b(zip64_extra) if e.local_file_header_offset == 0xFFFFFFFF_u64
    end

    e
  end

  private def read_local_headers_for(entries : Array(ZipEntry), io)
    entries.each do |entry|
      off = get_compressed_data_offset(io, entry.local_file_header_offset)
      entry.compressed_data_offset = off
    end
  end

  private def skip_ahead_2(io)
    skip_ahead_n(io, 2)
  end

  private def skip_ahead_4(io)
    skip_ahead_n(io, 4)
  end

  private def skip_ahead_8(io)
    skip_ahead_n(io, 8)
  end

  private def seek(io, absolute_pos)
    io.seek(absolute_pos.to_i64, IO::Seek::Set)
    unless absolute_pos.to_i64 == io.pos.to_i64
      raise ReadError.new("Expected to seek to #{absolute_pos} but only got to #{io.pos}")
    end
  end

  private def assert_signature(io, signature_magic_number : UInt32)
    readback = read_4b(io)
    if readback != signature_magic_number
      expected = "0x0" + signature_magic_number.to_s(16)
      actual = "0x0" + readback.to_s(16)
      raise InvalidStructure.new("Expected signature #{expected}, but read #{actual}")
    end
  end

  private def skip_ahead_n(io, n : Int)
    pos_before = io.pos.to_i64
    io.seek(pos_before + n, IO::Seek::Set)
    pos_after = io.pos.to_i64
    delta = pos_after - pos_before
    unless delta == n
      raise ReadError.new("Expected to seek #{n} bytes ahead, but could only seek #{delta} bytes ahead")
    end
  end

  private def read_n(io, n_bytes : Int) : Bytes
    buf = Bytes.new(n_bytes)
    io.read_fully(buf)
    buf
  rescue IO::EOFError
    raise ReadError.new("Expected to read #{n_bytes} bytes, but the IO was at the end")
  end

  private def read_2b(io) : UInt16
    IO::ByteFormat::LittleEndian.decode(UInt16, read_n(io, 2))
  end

  private def read_4b(io) : UInt32
    IO::ByteFormat::LittleEndian.decode(UInt32, read_n(io, 4))
  end

  private def read_8b(io) : UInt64
    IO::ByteFormat::LittleEndian.decode(UInt64, read_n(io, 8))
  end

  private def get_eocd_offset(file_io, zip_file_size : Int64) : Int64
    implied_position = zip_file_size - MAX_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE
    implied_position = 0_i64 if implied_position < 0

    file_io.seek(implied_position, IO::Seek::Set)
    buf = Bytes.new(MAX_END_OF_CENTRAL_DIRECTORY_RECORD_SIZE)
    bytes_read = file_io.read(buf)
    actual_buf = buf[0, bytes_read]
    eocd_idx_in_buf = locate_eocd_signature(actual_buf)

    raise MissingEOCD.new unless eocd_idx_in_buf

    implied_position + eocd_idx_in_buf
  end

  private def all_indices_of_substr_in_bytes(needle : Bytes, haystack : Bytes) : Array(Int32)
    found = [] of Int32
    i = 0
    while i <= haystack.size - needle.size
      if haystack[i, needle.size] == needle
        found << i
        i += needle.size
      else
        i += 1
      end
    end
    found
  end

  # We have to scan the maximum possible number of bytes that the EOCD can
  # theoretically occupy including the comment after it, and we have to find
  # a combination of:
  #   [EOCD signature, <some ZIP metadata>, comment byte size, comment of size]
  # at the end.
  private def locate_eocd_signature(in_bytes : Bytes) : Int64?
    eocd_signature_bytes = Bytes[0x50, 0x4b, 0x05, 0x06] # 0x06054b50 in LE
    minimum_record_size = 22

    indices = all_indices_of_substr_in_bytes(eocd_signature_bytes, in_bytes)
    indices.each do |check_at|
      maybe_record = in_bytes[check_at..]
      break if maybe_record.size < minimum_record_size

      # comment_size is at offset 20 from start of EOCD record
      comment_size = IO::ByteFormat::LittleEndian.decode(UInt16, maybe_record[20, 2])
      if (maybe_record.size - minimum_record_size) == comment_size
        return check_at.to_i64
      end
    end
    nil
  end

  # Find the Zip64 EOCD locator segment offset
  private def get_zip64_eocd_location(file_io, eocd_offset : Int64) : Int64?
    zip64_eocd_loc_offset = eocd_offset
    zip64_eocd_loc_offset -= 4 # The signature
    zip64_eocd_loc_offset -= 4 # Which disk has the Zip64 end of central directory record
    zip64_eocd_loc_offset -= 8 # Offset of the zip64 central directory record
    zip64_eocd_loc_offset -= 4 # Total number of disks

    # If the offset is negative there is certainly no Zip64 EOCD locator here
    return nil unless zip64_eocd_loc_offset >= 0

    file_io.seek(zip64_eocd_loc_offset, IO::Seek::Set)
    assert_signature(file_io, 0x07064b50_u32)

    disk_num = read_4b(file_io)
    raise UnsupportedFeature.new("The archive spans multiple disks") if disk_num != 0
    read_8b(file_io).to_i64
  rescue ReadError
    nil
  end

  private def num_files_and_central_directory_offset_zip64(io, zip64_end_of_cdir_location : Int64) : {Int64, Int64, Int64}
    seek(io, zip64_end_of_cdir_location)

    assert_signature(io, 0x06064b50_u32)

    zip64_eocdr_size = read_8b(io)
    zip64_eocdr_bytes = read_n(io, zip64_eocdr_size.to_i32)
    zip64_eocdr = IO::Memory.new
    zip64_eocdr.write(zip64_eocdr_bytes)
    zip64_eocdr.rewind
    skip_ahead_2(zip64_eocdr) # version made by
    skip_ahead_2(zip64_eocdr) # version needed to extract

    disk_n = read_4b(zip64_eocdr)
    disk_n_with_eocdr = read_4b(zip64_eocdr)
    raise UnsupportedFeature.new("The archive spans multiple disks") if disk_n != disk_n_with_eocdr

    num_files_this_disk = read_8b(zip64_eocdr)
    num_files_total = read_8b(zip64_eocdr)

    raise UnsupportedFeature.new("The archive spans multiple disks") if num_files_this_disk != num_files_total

    central_dir_size = read_8b(zip64_eocdr)
    central_dir_offset = read_8b(zip64_eocdr)

    {num_files_total.to_i64, central_dir_offset.to_i64, central_dir_size.to_i64}
  end

  private def num_files_and_central_directory_offset(file_io, eocd_offset : Int64) : {Int64, Int64, Int64}
    seek(file_io, eocd_offset)

    eocd_record_bytes = read_n(file_io, SIZE_OF_USABLE_EOCD_RECORD)
    io = IO::Memory.new
    io.write(eocd_record_bytes)
    io.rewind

    assert_signature(io, 0x06054b50_u32)
    skip_ahead_2(io) # number_of_this_disk
    skip_ahead_2(io) # number of the disk with the EOCD record
    skip_ahead_2(io) # number of entries in the central directory of this disk
    num_files = read_2b(io)
    cdir_size = read_4b(io)
    cdir_offset = read_4b(io)
    {num_files.to_i64, cdir_offset.to_i64, cdir_size.to_i64}
  end

  private def parse_out_extra_fields(extra_fields_bytes : Bytes) : Hash(UInt16, Bytes)
    extra_table = {} of UInt16 => Bytes
    extras_buf = IO::Memory.new
    extras_buf.write(extra_fields_bytes)
    extras_buf.rewind
    while extras_buf.pos < extras_buf.size
      extra_id = read_2b(extras_buf)
      extra_size = read_2b(extras_buf)
      extra_contents = read_n(extras_buf, extra_size.to_i32)
      extra_table[extra_id] = extra_contents
    end
    extra_table
  end

  # Stub for logging - override in a subclass if you need it
  private def log
  end
end
