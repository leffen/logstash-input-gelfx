# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/gelf"
require_relative "../support/helpers"
require "gelf"
require "flores/random"

describe LogStash::Inputs::Gelf do
  context "when interrupting the plugin" do
    let(:port) { Flores::Random.integer(1024..65535) }
    let(:host) { "127.0.0.1" }
    let(:chunksize) { 1420 }
    let(:producer) { InfiniteGelfProducer.new(host, port, chunksize) }
    let(:config) { {"host" => host, "port" => port} }

    before { producer.run }
    after { producer.stop }


    it_behaves_like "an interruptible input plugin"
  end

  it "reads chunked gelf messages " do
    port = 12209
    host = "127.0.0.1"
    chunksize = 1420
    gelfclient = GELF::Notifier.new(host, port, chunksize)

    conf = <<-CONFIG
      input {
        gelfx {
          port => "#{port}"
          host => "#{host}"
        }
      }
    CONFIG

    large_random = 2000.times.map { 32 + rand(126 - 32) }.join("")

    messages = [
      "hello",
      "world",
      large_random,
      "we survived gelf!"
    ]

    events = input(conf) do |pipeline, queue|
      # send a first message until plugin is up and receives it
      while queue.size <= 0
        gelfclient.notify!("short_message" => "prime")
        sleep(0.1)
      end
      gelfclient.notify!("short_message" => "start")

      e = queue.pop
      while (e.get("message") != "start")
        e = queue.pop
      end

      messages.each do |m|
        gelfclient.notify!("short_message" => m)
      end

      messages.map { queue.pop }
    end

    events.each_with_index do |e, i|
      insist { e.get("message") } == messages[i]
      insist { e.get("host") } == Socket.gethostname
    end
  end


  context "when an invalid JSON is fed to the listener" do
    subject { LogStash::Inputs::Gelf.new_event(message, "host") }
    let(:message) { "Invalid JSON message" }

    context "default :from_json parser output" do
      it { should be_a(LogStash::Event) }

      it "falls back to plain-text" do
        expect(subject.get("message")).to eq(message)
      end

      it "tags message with _jsonparsefailure" do
        expect(subject.get("tags")).to include("_jsonparsefailure")
      end

      it "tags message with _fromjsonparser" do
        expect(subject.get("tags")).to include("_fromjsonparser")
      end
    end
  end
end
