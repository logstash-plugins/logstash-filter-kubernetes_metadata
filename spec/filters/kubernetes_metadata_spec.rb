# base don https://github.com/logstash-plugins/logstash-output-http/blob/master/spec/outputs/http_spec.rb

require "spec_helper"
require "logstash/filters/kubernetes_metadata"
require "logstash/json"
require "sinatra"
require "thread"

PORT = rand(65535-1024) + 1025


class TestApp < Sinatra::Base

  # disable WEBrick logging
  def self.server_settings
    { :AccessLog => [], :Logger => WEBrick::BasicLog::new(nil, WEBrick::BasicLog::FATAL) }
  end

  get '/api/v1/namespaces/default/pods/kube-testwithsinglelogformat-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
          'log-format' => 'single_format'
        }
      }
     )
  end

  get '/api/v1/namespaces/default/pods/kube-testwithcontainername-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
          'log-format-stdout-myappname' => 'format_stdout',
          'log-format-stderr-myappname' => 'format_stderr'
        }
      }
     )
  end

  get '/api/v1/namespaces/default/pods/kube-testwithlogformat-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
          'log-format-stderr' => 'stderr_format',
          'log-format-stdout' => 'stdout_format'
        }
      }
    )
  end

  get '/api/v1/namespaces/default/pods/kube-testwithpartialdefault-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
          'log-format-stdout' => 'stdout_format'
        }
      }
    )
  end

  get '/api/v1/namespaces/default/pods/kube-testnologformat-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
        }
      }
    )
  end

  get '/api/v1/namespaces/default/pods/kube-testbadcharinannotations-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname"
        },
        annotations: {
          'kubernetes.io/created-by,' => '{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"DaemonSet\",\"namespace\":\"kube-system\",\"name\":\"sysdig-agent\",\"uid\":\"65cd1895-a7e7-11e5-8514-0ae32f64a3ed\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"5896462\"}}\n'
        }
      }
    )
  end

  get '/api/v1/namespaces/default/pods/kube-testbadcharinlabels-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
          app: "myappname",
          "test.label" => "my value"
        }
      }
    )
  end

  get '/api/v1/namespaces/default/pods/kube-testnometadata-abcde' do
     LogStash::Json.dump(
      metadata: {
        labels: {
        },
        annotations: {
        }
      }
    )
  end
end

RSpec.configure do |config|
  #http://stackoverflow.com/questions/6557079/start-and-call-ruby-http-server-in-the-same-script
  def sinatra_run_wait(app, opts)
    queue = Queue.new

    Thread.new(queue) do |queue|
      begin
        app.run!(opts) do |server|
          queue.push("started")
        end
      rescue
        # ignore
      end
    end

    queue.pop # blocks until the run! callback runs
  end

  config.before(:suite) do
    sinatra_run_wait(TestApp, :port => PORT, :server => 'webrick')
  end
end

describe LogStash::Filters::KubernetesMetadata do

  describe "Get pod metadata with non standard source" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
          source => "source"
          api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("source" => "/var/log/containers/kube-testwithsinglelogformat-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')

      expect(kubernetes['pod']).to eq('kube-testwithsinglelogformat-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testwithsinglelogformat')
      expect(kubernetes['annotations']['log-format']).to be_kind_of(String)
      expect(kubernetes['log_format_stdout']).to eq('single_format')
      expect(kubernetes['log_format_stderr']).to eq('single_format')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end

  end
  describe "Get pod metadata with single log-format" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("path" => "/var/log/containers/kube-testwithsinglelogformat-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')

      expect(kubernetes['pod']).to eq('kube-testwithsinglelogformat-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testwithsinglelogformat')
      expect(kubernetes['annotations']['log-format']).to be_kind_of(String)
      expect(kubernetes['log_format_stdout']).to eq('single_format')
      expect(kubernetes['log_format_stderr']).to eq('single_format')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end

  end

  describe "Get pod metadata with container name via log-format-stdout-container and log-format-stderr-container" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("path" => "/var/log/containers/kube-testwithcontainername-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')
      expect(kubernetes['pod']).to eq('kube-testwithcontainername-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testwithcontainername')
      expect(kubernetes['annotations']['log-format-stdout-myappname']).to be_kind_of(String)
      expect(kubernetes['annotations']['log-format-stderr-myappname']).to be_kind_of(String)
      expect(kubernetes['log_format_stdout']).to eq('format_stdout')
      expect(kubernetes['log_format_stderr']).to eq('format_stderr')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end

  end

  describe "Get pod metadata with both log-format-stderr and log-format-stdout" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("path" => "/var/log/containers/kube-testwithlogformat-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')
      expect(kubernetes['pod']).to eq('kube-testwithlogformat-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testwithlogformat')
      expect(kubernetes['annotations']['log-format-stdout']).to be_kind_of(String)
      expect(kubernetes['annotations']['log-format-stderr']).to be_kind_of(String)
      expect(kubernetes['log_format_stdout']).to eq('stdout_format')
      expect(kubernetes['log_format_stderr']).to eq('stderr_format')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end

  end

  describe "Get pod metadata with partial default" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    #do more than once to make sure caching returns expected value
    (0..2).each do |i|
      sample("path" => "/var/log/containers/kube-testwithpartialdefault-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e2439850#{i}.log") do
        kubernetes = subject.get('kubernetes')
        expect(kubernetes).to be_a(Hash)
        expect(kubernetes['pod']).to eq('kube-testwithpartialdefault-abcde')
        expect(kubernetes['namespace']).to eq('default')
        expect(kubernetes['container_name']).to eq('myappname')
        expect(kubernetes['replication_controller']).to eq('kube-testwithpartialdefault')
        expect(kubernetes['labels']['app']).to eq('myappname')
        expect(kubernetes['log_format_stderr']).to eq('default')
        expect(kubernetes['log_format_stdout']).to eq('stdout_format')
      end
    end
  end

  describe "Get pod metadata with no log-format" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("path" => "/var/log/containers/kube-testnologformat-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')
      expect(kubernetes['pod']).to eq('kube-testnologformat-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testnologformat')
      expect(kubernetes['log_format_stdout']).to eq('default')
      expect(kubernetes['log_format_stderr']).to eq('default')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end
  end

  describe "Get pod metadata with no bad character in annotations key name" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    sample("path" => "/var/log/containers/kube-testbadcharinannotations-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
      kubernetes = subject.get('kubernetes')
      expect(kubernetes['pod']).to eq('kube-testbadcharinannotations-abcde')
      expect(kubernetes['namespace']).to eq('default')
      expect(kubernetes['container_name']).to eq('myappname')
      expect(kubernetes['replication_controller']).to eq('kube-testbadcharinannotations')
      expect(kubernetes['annotations']['kubernetes.io/created-by']).to be_falsey
      expect(kubernetes['annotations']['kubernetes_io-created-by_']).to be_kind_of(String)
      expect(kubernetes['log_format_stderr']).to eq('default')
      expect(kubernetes['labels']['app']).to eq('myappname')
    end
  end

  describe "Get pod metadata with no bad character in label key name" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    (0..2).each do |i|
      sample("path" => "/var/log/containers/kube-testbadcharinlabels-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
        kubernetes = subject.get('kubernetes')
        expect(kubernetes['pod']).to eq('kube-testbadcharinlabels-abcde')
        expect(kubernetes['namespace']).to eq('default')
        expect(kubernetes['container_name']).to eq('myappname')
        expect(kubernetes['replication_controller']).to eq('kube-testbadcharinlabels')
        expect(kubernetes['labels']['test.label']).to be_falsey
        expect(kubernetes['labels']['test_label']).to be_kind_of(String)
        expect(kubernetes['log_format_stderr']).to eq('default')
        expect(kubernetes['labels']['app']).to eq('myappname')
      end
    end
  end

  describe "Get pod metadata with no metadata" do
    let(:config) do <<-CONFIG
      filter {
        kubernetes_metadata {
            api => "http://127.0.0.1:#{PORT}"
        }
      }
    CONFIG
    end

    (0..2).each do |i|
      sample("path" => "/var/log/containers/kube-testnometadata-abcde_default_myappname-47d3a3bfb112dbd2fd6e255e1e3d9eb91a10b62342e620e4917e2f5e24398507.log") do
        kubernetes = subject.get('kubernetes')
        expect(kubernetes['pod']).to eq('kube-testnometadata-abcde')
        expect(kubernetes['namespace']).to eq('default')
        expect(kubernetes['container_name']).to eq('myappname')
        expect(kubernetes['replication_controller']).to eq('kube-testnometadata')
        expect(kubernetes['log_format_stderr']).to eq('default')
      end
    end
  end
end
