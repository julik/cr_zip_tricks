require "./spec_helper"

describe ZipTricks::Streamer do
  describe "#add_empty_directory" do
    it "adds a directory entry with trailing slash" do
      buf = IO::Memory.new
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_empty_directory("my_directory")
      end
      buf.rewind
      # The archive should contain an entry named "my_directory/"
      buf.to_s.should contain("my_directory/")
    end

    it "does not double the trailing slash if already present" do
      buf = IO::Memory.new
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_empty_directory("my_directory/")
      end
      buf.rewind
      # Should have only one trailing slash
      buf.to_s.scan("my_directory/").size.should be >= 1
      buf.to_s.should_not contain("my_directory//")
    end
  end

  describe "#add_stored" do
    it "accepts modification_time parameter" do
      buf = IO::Memory.new
      custom_time = Time.utc(2020, 6, 15, 10, 30, 0)
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_stored("test.txt", modification_time: custom_time) do |io|
          io << "Hello"
        end
      end
      buf.size.should be > 0
    end

    it "accepts unix_permissions parameter" do
      buf = IO::Memory.new
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_stored("test.txt", unix_permissions: 0o755) do |io|
          io << "Hello"
        end
      end
      buf.size.should be > 0
    end
  end

  describe "#add_deflated" do
    it "accepts modification_time parameter" do
      buf = IO::Memory.new
      custom_time = Time.utc(2019, 3, 20, 14, 45, 0)
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_deflated("test.txt", modification_time: custom_time) do |io|
          io << "Hello World, this is some text that should compress well!"
        end
      end
      buf.size.should be > 0
    end

    it "accepts unix_permissions parameter" do
      buf = IO::Memory.new
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_deflated("test.txt", unix_permissions: 0o600) do |io|
          io << "Secret content"
        end
      end
      buf.size.should be > 0
    end
  end

  describe "#simulate_write" do
    it "advances the internal offset" do
      buf = IO::Memory.new
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_stored_entry("test.bin", size: 100, crc32: 12345)
      initial_offset = streamer.bytesize
      streamer.simulate_write(100)
      streamer.bytesize.should eq(initial_offset + 100)
    end
  end

  describe "#add_stored_entry" do
    it "writes a local header for a stored entry with known size" do
      buf = IO::Memory.new
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_stored_entry("test.bin", size: 100, crc32: 12345)
      buf.size.should be > 0
    end

    it "accepts modification_time parameter" do
      buf = IO::Memory.new
      custom_time = Time.utc(2021, 1, 1, 0, 0, 0)
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_stored_entry("test.bin", modification_time: custom_time, size: 0, crc32: 0)
      buf.size.should be > 0
    end

    it "accepts unix_permissions parameter" do
      buf = IO::Memory.new
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_stored_entry("test.bin", unix_permissions: 0o777, size: 0, crc32: 0)
      buf.size.should be > 0
    end
  end

  describe "#add_deflated_entry" do
    it "writes a local header for a deflated entry with known sizes" do
      buf = IO::Memory.new
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_deflated_entry("test.bin", compressed_size: 50, uncompressed_size: 100, crc32: 12345)
      buf.size.should be > 0
    end
  end

  describe "backslash handling" do
    it "converts backslashes to underscores in filenames" do
      buf = IO::Memory.new
      ZipTricks::Streamer.archive(buf) do |s|
        s.add_stored("path\\to\\file.txt") do |io|
          io << "content"
        end
      end
      buf.rewind
      buf.to_s.should contain("path_to_file.txt")
      buf.to_s.should_not contain("path\\to\\file.txt")
    end
  end

  describe "exception classes" do
    it "raises DuplicateFilename for duplicate filenames" do
      buf = IO::Memory.new
      expect_raises(ZipTricks::Streamer::DuplicateFilename) do
        ZipTricks::Streamer.archive(buf) do |s|
          s.add_stored("test.txt") { |io| io << "first" }
          s.add_stored("test.txt") { |io| io << "second" }
        end
      end
    end

    it "raises Overflow for filenames that are too long" do
      buf = IO::Memory.new
      long_filename = "a" * 70000 # > 0xFFFF bytes
      expect_raises(ZipTricks::Streamer::Overflow) do
        ZipTricks::Streamer.archive(buf) do |s|
          s.add_stored(long_filename) { |io| io << "content" }
        end
      end
    end

    it "defines UnknownMode exception class" do
      # Verify the exception class exists for invalid storage modes
      ZipTricks::Streamer::UnknownMode.should be_truthy
    end
  end

  describe "#update_last_entry_and_write_data_descriptor" do
    it "updates the last entry and writes a data descriptor" do
      buf = IO::Memory.new
      streamer = ZipTricks::Streamer.new(buf)
      streamer.add_stored_entry("test.bin", use_data_descriptor: true)
      streamer.simulate_write(100)
      offset = streamer.update_last_entry_and_write_data_descriptor(
        crc32: 12345,
        compressed_size: 100,
        uncompressed_size: 100)
      offset.should be > 0
    end
  end
end
