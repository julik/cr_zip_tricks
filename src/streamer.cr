require "./writer"
require "./offset_io"
require "./crc32_writer"
require "compress/deflate"

class ZipTricks::Streamer
  STORED   = 0
  DEFLATED = 8

  class DuplicateFilename < ArgumentError
  end

  class Overflow < ArgumentError
  end

  class UnknownMode < ArgumentError
  end

  class OffsetOutOfSync < Exception
  end

  class Entry
    property filename = ""
    property entry_offset_in_file = 0_u64
    property crc32 = Digest::CRC32.initial
    property uncompressed_size = 0_u64
    property compressed_size = 0_u64
    property use_data_descriptor = false
    property storage_mode = 0 # Stored
    property mtime : Time = Time.utc
    property unix_permissions : Int32? = nil
    property bytes_used_for_local_header = 0_u64
    property bytes_used_for_data_descriptor = 0_u64

    # Get the general purpose flags for the entry. We care about is the EFS
    # bit (bit 11) which should be set if the filename is UTF8. If it is, we need to set the
    # bit so that the unarchiving application knows that the filename in the archive is UTF-8
    # encoded, and not some DOS default. For ASCII entries it does not matter.
    # Additionally, we care about bit 3 which toggles the use of the postfix data descriptor.

    def gp_flags
      flag = 0b00000000000
      flag |= 0b100000000000                 # if @requires_efs_flag # bit 11
      flag |= 0x0008 if @use_data_descriptor # bit 3
      flag
    end

    # Returns the total bytes used by this entry in the archive
    # (local header + compressed data + data descriptor)
    def total_bytes_used
      bytes_used_for_local_header + compressed_size + bytes_used_for_data_descriptor
    end
  end

  def initialize(io : IO)
    @raw_io = io
    @io = ZipTricks::OffsetIO.new(@raw_io)
    @filenames = Set(String).new
    @entries = Array(Entry).new
    @writer = ZipTricks::Writer.new
  end

  def self.archive(io : IO, &)
    streamer = new(io)
    yield streamer
    streamer.finish
  end

  def finish
    verify_offsets!
    write_central_directory
    @filenames.clear
    @entries.clear
  end

  # Advances the internal IO pointer to keep the offsets of the ZIP file in
  # check. Use this if you are going to use accelerated writes to the socket
  # (like the `sendfile()` call) after writing the headers, or if you
  # just need to figure out the size of the archive.
  #
  # Returns the current position in the output stream / ZIP archive.
  def simulate_write(num_bytes : Int)
    @io.advance(num_bytes)
    @io.offset
  end

  # Writes out the local header for an entry (file in the ZIP) that is using
  # the stored storage model (is stored as-is).
  # Once this method is called, you need to write the actual contents of the body
  # and then call simulate_write with the number of bytes written.
  #
  # @param filename the name of the file in the entry
  # @param modification_time the modification time of the file in the archive
  # @param size the size of the file when uncompressed, in bytes
  # @param crc32 the CRC32 checksum of the entry when uncompressed
  # @param unix_permissions which UNIX permissions to set, or nil for the default
  # @param use_data_descriptor whether the entry body will be followed by a data descriptor
  # @return the offset the output IO is at after writing the entry header
  def add_stored_entry(filename : String, modification_time : Time = Time.utc, size : Int = 0, crc32 : Int = 0, unix_permissions : Int? = nil, use_data_descriptor : Bool = false)
    add_file_and_write_local_header(
      filename: filename,
      modification_time: modification_time,
      crc32: crc32,
      storage_mode: STORED,
      compressed_size: size,
      uncompressed_size: size,
      unix_permissions: unix_permissions,
      use_data_descriptor: use_data_descriptor)
    @io.offset
  end

  # Writes out the local header for an entry (file in the ZIP) that is using
  # the deflated storage model (is compressed).
  # Once this method is called, you need to write the actual compressed contents
  # and then call simulate_write with the number of bytes written.
  #
  # Note that the deflated body that is going to be written into the output
  # has to be _precompressed_ (pre-deflated) before writing it into the
  # Streamer, because otherwise it is impossible to know it's size upfront.
  #
  # @param filename the name of the file in the entry
  # @param modification_time the modification time of the file in the archive
  # @param compressed_size the size of the compressed entry
  # @param uncompressed_size the size of the entry when uncompressed, in bytes
  # @param crc32 the CRC32 checksum of the entry when uncompressed
  # @param unix_permissions which UNIX permissions to set, or nil for the default
  # @param use_data_descriptor whether the entry body will be followed by a data descriptor
  # @return the offset the output IO is at after writing the entry header
  def add_deflated_entry(filename : String, modification_time : Time = Time.utc, compressed_size : Int = 0, uncompressed_size : Int = 0, crc32 : Int = 0, unix_permissions : Int? = nil, use_data_descriptor : Bool = false)
    add_file_and_write_local_header(
      filename: filename,
      modification_time: modification_time,
      crc32: crc32,
      storage_mode: DEFLATED,
      compressed_size: compressed_size,
      uncompressed_size: uncompressed_size,
      unix_permissions: unix_permissions,
      use_data_descriptor: use_data_descriptor)
    @io.offset
  end

  # Adds an empty directory to the archive with a size of 0 and permissions of 755.
  #
  # @param dirname the name of the directory in the archive
  # @param modification_time the modification time of the directory in the archive
  # @param unix_permissions which UNIX permissions to set, or nil for the default (0o755)
  # @return the offset the output IO is at after writing the entry header
  def add_empty_directory(dirname : String, modification_time : Time = Time.utc, unix_permissions : Int? = nil)
    # Ensure dirname ends with "/"
    dirname = dirname + "/" unless dirname.ends_with?("/")
    add_file_and_write_local_header(
      filename: dirname,
      modification_time: modification_time,
      crc32: 0,
      storage_mode: STORED,
      compressed_size: 0,
      uncompressed_size: 0,
      unix_permissions: unix_permissions,
      use_data_descriptor: false)
    @io.offset
  end

  # Updates the last entry written with the CRC32 checksum and compressed/uncompressed
  # sizes. For stored entries, compressed_size and uncompressed_size are the same.
  # After updating the entry will immediately write the data descriptor bytes
  # to the output.
  #
  # @param crc32 the CRC32 checksum of the entry when uncompressed
  # @param compressed_size the size of the compressed segment within the ZIP
  # @param uncompressed_size the size of the entry once uncompressed
  # @return the offset the output IO is at after writing the data descriptor
  def update_last_entry_and_write_data_descriptor(crc32 : Int, compressed_size : Int, uncompressed_size : Int)
    last_entry = @entries.last
    last_entry.crc32 = crc32.to_u32
    last_entry.compressed_size = compressed_size.to_u64
    last_entry.uncompressed_size = uncompressed_size.to_u64

    offset_before_data_descriptor = @io.offset
    @writer.write_data_descriptor(io: @io,
      compressed_size: last_entry.compressed_size,
      uncompressed_size: last_entry.uncompressed_size,
      crc32: last_entry.crc32)
    last_entry.bytes_used_for_data_descriptor = @io.offset - offset_before_data_descriptor

    @io.offset
  end

  def add_stored(filename : String, modification_time : Time = Time.utc, unix_permissions : Int? = nil, &)
    add_file_and_write_local_header(
      filename: filename,
      modification_time: modification_time,
      crc32: 0,
      storage_mode: STORED,
      compressed_size: 0,
      uncompressed_size: 0,
      unix_permissions: unix_permissions,
      use_data_descriptor: true)

    sizer = ZipTricks::OffsetIO.new(@io)
    checksum = ZipTricks::CRC32Writer.new(sizer)

    yield checksum # for writing, the caller can write to it as an IO

    last_entry = @entries.last
    last_entry.uncompressed_size = sizer.offset
    last_entry.compressed_size = sizer.offset
    last_entry.crc32 = checksum.crc32
    write_data_descriptor_for_last_entry
  end

  def add_deflated(filename : String, modification_time : Time = Time.utc, unix_permissions : Int? = nil, &)
    add_file_and_write_local_header(
      filename: filename,
      modification_time: modification_time,
      crc32: 0,
      storage_mode: DEFLATED,
      compressed_size: 0,
      uncompressed_size: 0,
      unix_permissions: unix_permissions,
      use_data_descriptor: true)

    # The "IO sandwich"
    compressed_sizer = ZipTricks::OffsetIO.new(@io)
    flater_io = Compress::Deflate::Writer.new(compressed_sizer)
    uncompressed_sizer = ZipTricks::OffsetIO.new(flater_io)
    checksum = ZipTricks::CRC32Writer.new(uncompressed_sizer)

    yield checksum # for writing, the caller can write to it as an IO

    flater_io.close # To finish generating the deflated block
    last_entry = @entries.last
    last_entry.uncompressed_size = uncompressed_sizer.offset
    last_entry.compressed_size = compressed_sizer.offset
    last_entry.crc32 = checksum.crc32
    write_data_descriptor_for_last_entry
  end

  def write_data_descriptor_for_last_entry
    entry = @entries[-1]
    offset_before = @io.offset
    @writer.write_data_descriptor(io: @io,
      compressed_size: entry.compressed_size,
      uncompressed_size: entry.uncompressed_size,
      crc32: entry.crc32)
    entry.bytes_used_for_data_descriptor = @io.offset - offset_before
  end

  def write_local_entry_header(entry)
    offset_before = @io.offset
    @writer.write_local_file_header(io: @io,
      filename: entry.filename,
      compressed_size: entry.compressed_size,
      uncompressed_size: entry.uncompressed_size,
      crc32: entry.crc32,
      gp_flags: entry.gp_flags,
      mtime: entry.mtime,
      storage_mode: entry.storage_mode)
    entry.bytes_used_for_local_header = @io.offset - offset_before
  end

  # Legacy method - use simulate_write instead for clarity
  def advance(by)
    @io.advance(by)
  end

  def bytesize
    @io.offset
  end

  def write_central_directory
    cdir_starts_at = @io.offset
    @entries.each do |entry|
      @writer.write_central_directory_file_header(io: @io,
        filename: entry.filename,
        compressed_size: entry.compressed_size,
        uncompressed_size: entry.uncompressed_size,
        crc32: entry.crc32,
        gp_flags: entry.gp_flags,
        mtime: entry.mtime,
        storage_mode: entry.storage_mode,
        local_file_header_location: entry.entry_offset_in_file,
        unix_permissions: entry.unix_permissions)
    end
    cdir_ends_at = @io.offset
    cdir_size = cdir_ends_at - cdir_starts_at
    @writer.write_end_of_central_directory(io: @io,
      start_of_central_directory_location: cdir_starts_at,
      central_directory_size: @io.offset - cdir_starts_at,
      num_files_in_archive: @entries.size)
  end

  private def check_dupe_filename!(filename)
    if @filenames.includes?(filename)
      raise(DuplicateFilename.new("The archive already contains an entry named #{filename.inspect}"))
    else
      @filenames.add(filename)
    end
  end

  # Cleans up backslashes in filenames (Windows-style paths)
  private def remove_backslash(filename : String) : String
    filename.tr("\\", "_")
  end

  # Verifies that the offsets tracked by entries match the actual IO position
  private def verify_offsets!
    computed_offset = @entries.sum(&.total_bytes_used)
    actual_offset = @io.offset
    if computed_offset != actual_offset
      raise OffsetOutOfSync.new(
        "The offset of the Streamer output IO is out of sync with the expected value. " \
        "Entries add up to #{computed_offset} bytes but the IO is at #{actual_offset} bytes. " \
        "This can happen if you write data directly to the IO without calling simulate_write().")
    end
  end

  private def add_file_and_write_local_header(
    filename : String,
    modification_time : Time,
    crc32 : Int,
    storage_mode : Int,
    compressed_size : Int,
    uncompressed_size : Int,
    unix_permissions : Int?,
    use_data_descriptor : Bool,
  )
    # Clean backslashes
    filename = remove_backslash(filename)

    # Validate storage mode
    unless storage_mode == STORED || storage_mode == DEFLATED
      raise UnknownMode.new("Unknown compression mode #{storage_mode}")
    end

    # Validate filename length
    if filename.bytesize > 0xFFFF
      raise Overflow.new("Filename is too long (#{filename.bytesize} bytes, max 65535)")
    end

    check_dupe_filename!(filename)

    # If using data descriptor, sizes and crc32 are written after the data
    if use_data_descriptor
      crc32 = 0
      compressed_size = 0
      uncompressed_size = 0
    end

    entry = Entry.new
    entry.filename = filename
    entry.mtime = modification_time
    entry.unix_permissions = unix_permissions.try(&.to_i32)
    entry.use_data_descriptor = use_data_descriptor
    entry.storage_mode = storage_mode
    entry.entry_offset_in_file = @io.offset
    entry.uncompressed_size = uncompressed_size.to_u64
    entry.compressed_size = compressed_size.to_u64
    entry.crc32 = crc32.to_u32

    @entries << entry
    write_local_entry_header(entry)
  end
end
