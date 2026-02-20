require "./spec_helper"
require "digest/crc32"

class ReadMonitor < IO
  getter num_reads = 0

  def initialize(@io : IO::Memory)
  end

  def read(slice : Bytes) : Int32
    @num_reads += 1
    @io.read(slice)
  end

  def write(slice : Bytes) : Nil
    @io.write(slice)
  end

  delegate :pos, :seek, :size, :rewind, to: @io
end

describe ZipTricks::FileReader do
  context "with a file without EOCD" do
    it "raises the MissingEOCD exception and refuses to read" do
      f = IO::Memory.new
      10.times { f << ("A" * 1024) }
      f.rewind

      expect_raises(ZipTricks::FileReader::MissingEOCD) do
        ZipTricks::FileReader.read_zip_structure(f)
      end
    end
  end

  describe "read_zip_straight_ahead" do
    it "returns all the entries it can recover" do
      zipfile = IO::Memory.new
      war_and_peace = File.read(__DIR__ + "/war-and-peace.txt")
      crc = Digest::CRC32.checksum(war_and_peace)

      ZipTricks::Streamer.archive(zipfile) do |zip|
        zip.add_stored_entry(filename: "text1.txt",
          crc32: crc,
          size: war_and_peace.bytesize)
        zipfile.write(war_and_peace.to_slice)
        zip.simulate_write(war_and_peace.bytesize)

        zip.add_stored_entry(filename: "text2.txt",
          crc32: crc,
          size: war_and_peace.bytesize)
        zipfile.write(war_and_peace.to_slice)
        zip.simulate_write(war_and_peace.bytesize)

        zip.add_stored_entry(filename: "text3.txt",
          crc32: crc,
          size: war_and_peace.bytesize)
        zipfile.write(war_and_peace.to_slice)
        zip.simulate_write(war_and_peace.bytesize)
      end
      zipfile.rewind

      recovered_entries = ZipTricks::FileReader.read_zip_straight_ahead(zipfile)
      recovered_entries.size.should eq(3)
      recovered_entries.each do |entry|
        entry.storage_mode.should eq(0)
        entry.compressed_size.should eq(war_and_peace.bytesize)
        entry.uncompressed_size.should eq(war_and_peace.bytesize)
      end

      recovered_entries.each do |entry|
        zipfile.seek(entry.compressed_data_offset.to_i64, IO::Seek::Set)
        buf = Bytes.new(5)
        zipfile.read_fully(buf)
        buf.should eq(war_and_peace.to_slice[0, 5])
      end
    end

    it "recovers an entry that uses Zip64 extra fields" do
      zipfile = IO::Memory.new
      w = ZipTricks::Writer.new
      w.write_local_file_header(io: zipfile,
        filename: "big.bin",
        compressed_size: 0xFFFFFFFFFF_i64,
        uncompressed_size: 0xFFFFFFFFF_i64,
        crc32: 0,
        gp_flags: 0,
        mtime: Time.utc,
        storage_mode: 0)
      zipfile.rewind
      recovered_entries = ZipTricks::FileReader.read_zip_straight_ahead(zipfile)
      recovered_entries.size.should eq(1)
      entry = recovered_entries.first
      entry.compressed_size.should eq(0xFFFFFFFFFF_u64)
    end

    it "raises when an entry uses a data descriptor" do
      zipfile = IO::Memory.new
      ZipTricks::Streamer.archive(zipfile) do |zip|
        zip.add_deflated("war-and-peace.txt") do |sink|
          sink << File.read(__DIR__ + "/war-and-peace.txt")
        end
      end
      zipfile.rewind

      expect_raises(ZipTricks::FileReader::UnsupportedFeature) do
        ZipTricks::FileReader.read_zip_straight_ahead(zipfile)
      end
    end
  end

  context "with a ZIP file where the size of the central directory is recorded incorrectly" do
    it "is still able to read the entries" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        zip.add_deflated("text-1.txt") { |sink| sink << tolstoy }
        zip.add_deflated("text-2.txt") { |sink| sink << tolstoy }
      end

      # Find the start of the EOCD record
      zip_bytes = Bytes.new(zipfile.size)
      zipfile.rewind
      zipfile.read_fully(zip_bytes)

      eocd_sig = Bytes[0x50, 0x4b, 0x05, 0x06]
      eocd_offset = -1
      (0..zip_bytes.size - 4).each do |i|
        if zip_bytes[i, 4] == eocd_sig
          eocd_offset = i
        end
      end
      eocd_offset.should_not eq(-1)

      # Overwrite the central directory size field (at offset +12 from EOCD sig)
      # with a wrong value
      cdir_size_offset = eocd_offset + 12
      wrong_size = IO::ByteFormat::LittleEndian.decode(UInt32, zip_bytes[cdir_size_offset, 4]) + 64
      IO::ByteFormat::LittleEndian.encode(wrong_size, zip_bytes[cdir_size_offset, 4])

      damaged_zip = IO::Memory.new
      damaged_zip.write(zip_bytes)
      damaged_zip.rewind

      entries = ZipTricks::FileReader.read_zip_structure(damaged_zip)
      entries.size.should eq(2)
    end
  end

  context "with an end-to-end ZIP file to read" do
    it "reads and uncompresses the file written deflated with data descriptors" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        zip.add_deflated("war-and-peace.txt") do |sink|
          sink << tolstoy
        end
      end

      entries = ZipTricks::FileReader.read_zip_structure(zipfile)
      entries.size.should eq(1)

      entry = entries.first

      readback = IO::Memory.new
      reader = entry.extractor_from(zipfile)
      until reader.eof?
        chunk = reader.extract(10)
        readback.write(chunk) if chunk
      end

      readback.size.should eq(tolstoy.bytesize)
      readback.rewind
      readback_str = readback.gets_to_end
      readback_str[0..10].should eq(tolstoy[0..10])
      readback_str[-10..].should eq(tolstoy[-10..])
    end

    it "performs local file header reads by default" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        40.times do |i|
          zip.add_deflated(sprintf("war-and-peace-%d.txt", i)) { |sink| sink << tolstoy }
        end
      end
      zipfile.rewind

      read_monitor = ReadMonitor.new(zipfile)
      _entries = ZipTricks::FileReader.read_zip_structure(read_monitor, read_local_headers: true)
      read_monitor.num_reads.should eq(44)
    end

    it "performs local file header reads when `read_local_headers` is set to true" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        40.times do |i|
          zip.add_deflated(sprintf("war-and-peace-%d.txt", i)) { |sink| sink << tolstoy }
        end
      end
      zipfile.rewind

      read_monitor = ReadMonitor.new(zipfile)
      entries = ZipTricks::FileReader.read_zip_structure(read_monitor, read_local_headers: true)
      read_monitor.num_reads.should eq(44)

      entries.size.should eq(40)
      entry = entries.first
      entry.known_offset?.should be_true
    end

    it "performs a limited number of reads when `read_local_headers` is set to false" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        40.times do |i|
          zip.add_deflated(sprintf("war-and-peace-%d.txt", i)) { |sink| sink << tolstoy }
        end
      end
      zipfile.rewind

      read_monitor = ReadMonitor.new(zipfile)
      entries = ZipTricks::FileReader.read_zip_structure(read_monitor, read_local_headers: false)

      read_monitor.num_reads.should eq(4)
      entries.size.should eq(40)
      entry = entries.first
      entry.known_offset?.should be_false
      expect_raises(ZipTricks::FileReader::LocalHeaderPending) do
        entry.compressed_data_offset
      end
    end

    it "reads the file written stored with data descriptors" do
      zipfile = IO::Memory.new
      tolstoy = File.read(__DIR__ + "/war-and-peace.txt")

      ZipTricks::Streamer.archive(zipfile) do |zip|
        zip.add_stored("war-and-peace.txt") do |sink|
          sink << tolstoy
        end
      end

      entries = ZipTricks::FileReader.read_zip_structure(zipfile)
      entries.size.should eq(1)

      entry = entries.first

      readback = IO::Memory.new
      reader = entry.extractor_from(zipfile)
      until reader.eof?
        chunk = reader.extract
        readback.write(chunk) if chunk
      end

      readback.size.should eq(tolstoy.bytesize)
      readback.rewind
      readback_str = readback.gets_to_end
      readback_str[0..10].should eq(tolstoy[0..10])
    end
  end

  describe "#get_compressed_data_offset" do
    it "reads the offset for an entry having Zip64 extra fields" do
      w = ZipTricks::Writer.new
      buf = IO::Memory.new
      random_bytes = Random.new.random_bytes(7_656_177)
      buf.write(random_bytes)
      w.write_local_file_header(io: buf,
        filename: "some file",
        compressed_size: 0xFFFFFFFF_i64 + 5,
        uncompressed_size: 0xFFFFFFFFF_i64,
        crc32: 123,
        gp_flags: 4,
        mtime: Time.utc,
        storage_mode: 8)

      buf.rewind

      reader = ZipTricks::FileReader.new
      compressed_data_offset = reader.get_compressed_data_offset(buf,
        local_file_header_offset: 7_656_177)
      compressed_data_offset.should eq(7_656_245)
    end

    it "reads the offset for an entry having a long name" do
      w = ZipTricks::Writer.new
      buf = IO::Memory.new
      random_bytes = Random.new.random_bytes(7)
      buf.write(random_bytes)
      w.write_local_file_header(io: buf,
        filename: "This is a file with a ridiculously long name.doc",
        compressed_size: 10,
        uncompressed_size: 15,
        crc32: 123,
        gp_flags: 4,
        mtime: Time.utc,
        storage_mode: 8)

      buf.rewind

      reader = ZipTricks::FileReader.new
      compressed_data_offset = reader.get_compressed_data_offset(buf,
        local_file_header_offset: 7)
      compressed_data_offset.should eq(94)
    end
  end

  it "is able to latch to the EOCD location even if the signature appears all over the ZIP" do
    # A VERY evil ZIP file which has this signature all over
    eocd_sig = String.new(Bytes[0x50, 0x4b, 0x05, 0x06])
    evil_str = "#{eocd_sig} and #{eocd_sig}"

    z = IO::Memory.new
    w = ZipTricks::Writer.new
    w.write_local_file_header(io: z,
      filename: evil_str,
      compressed_size: evil_str.bytesize,
      uncompressed_size: evil_str.bytesize,
      crc32: 0x06054b50,
      gp_flags: 0,
      mtime: Time.utc,
      storage_mode: 0)
    z.write(evil_str.to_slice)
    where = z.pos
    w.write_central_directory_file_header(io: z,
      local_file_header_location: 0,
      gp_flags: 0,
      storage_mode: 0,
      filename: evil_str,
      compressed_size: evil_str.bytesize,
      uncompressed_size: evil_str.bytesize,
      mtime: Time.utc,
      crc32: 0x06054b50)
    w.write_end_of_central_directory(io: z,
      start_of_central_directory_location: where,
      central_directory_size: z.pos - where,
      num_files_in_archive: 1,
      comment: evil_str)

    z.rewind
    entries = ZipTricks::FileReader.read_zip_structure(z)
    entries.size.should eq(1)
  end

  it "can handle Zip64 central directory fields that only contain the required fields" do
    File.open(__DIR__ + "/cdir_entry_with_partial_use_of_zip64_extra_fields.bin", "rb") do |f|
      reader = ZipTricks::FileReader.new
      entry = reader.read_cdir_entry(f)
      entry.local_file_header_offset.should eq(4_312_401_349_u64)
      entry.filename.should eq("Motorhead - Ace Of Spades.srt")
      entry.compressed_size.should eq(69_121_u64)
      entry.uncompressed_size.should eq(69_121_u64)
    end
  end
end
