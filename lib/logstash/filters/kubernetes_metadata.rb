# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "lru_redux"
require "rest-client"
require "uri"
require "logstash/json"

# Kubernetes collects logs in files on each of its minion hosts. The filenames for
# these log files are structured to contain various information including the pod
# name, container id, namespace, etc...
#
# This plugin parses the information from these filenames, uses the information to
# query the kubernetes API for more information such as labels, and log format, and
# caches this information for fast subsequent lookups for matching filename parameters.
#
# The data collected is then added to the logstash event under the target field
# specified and returned for further processing or output.
#
# === Configuration
#
# The following is a basic configuration. Assuming your Kubernetes cluster does
# not require basic auth and it is running locally at http://127.0.0.1:8001, there
# are no required configuration options.
#
# Most users will at least want to specify an API server which would be done like so...
#
# [source, ruby]
# -----------------------------------------------------------------
# kubernetes_metadata {
#   api => "https://your.kube.api.server"
# }
# -----------------------------------------------------------------
#
# === Example Input/Output
#
# Given a log file: `/logs/kube-logs/ssl-manager-535881469-x6hmm_storj-prod_ssl-manager-c817d2905d339677288ff73375856a066d4b4d8d45482e1f2e234428d217eb19.log`
#
# and the contents:
# [source, json]
# -----------------------------------------------------------------
# {"log":"10.244.1.1 - - [25/Jan/2017:14:51:38 +0000] \"GET / HTTP/1.1\" 200 0 \"-\" \"GoogleHC/1.0\" \"-\"\n","stream":"stdout","time":"2017-01-25T14:51:38.65719468Z"}
# -----------------------------------------------------------------
#
# You would end up with an output of...
#
# [source, ruby]
# -----------------------------------------------------------------
# {
#   "path" => "/logs/kube-logs/ssl-manager-535881469-x6hmm_storj-prod_ssl-manager-c817d2905d339677288ff73375856a066d4b4d8d45482e1f2e234428d217eb19.log",
#   "kubernetes" => {
#     "log_format_stdout" => "default",
#     "pod" => "ssl-manager-535881469-x6hmm",
#     "container_name" => "ssl-manager",
#     "log_format_stderr" => "default",
#     "namespace" => "storj-prod",
#     "replication_controller" => "ssl-manager-535881469",
#     "annotations" => {
#       "kubernetes_io-created-by" => "{\"kind\":\"SerializedReference\",\"apiVersion\":\"v1\",\"reference\":{\"kind\":\"ReplicaSet\",\"namespace\":\"storj-prod\",\"name\":\"ssl-manager-535881469\",\"uid\":\"aca823ae-e271-11e6-99b2-42010a800002\",\"apiVersion\":\"extensions\",\"resourceVersion\":\"19491631\"}}\n"
#     },
#     "container_id" => "c817d2905d339677288ff73375856a066d4b4d8d45482e1f2e234428d217eb19",
#     "labels" => {
#       "app" => "ssl-manager",
#       "pod-template-hash" => "535881469",
#       "version" => "latest"
#     }
#   },
#   "@timestamp" => 2017-02-13T02:33:11.702Z,
#   "@version" => "1",
#   "host" => "floptop.local",
#   "message" => "{\"log\":\"10.244.1.1 - - [25/Jan/2017:14:51:38 +0000] \\\"GET / HTTP/1.1\\\" 200 0 \\\"-\\\" \\\"GoogleHC/1.0\\\" \\\"-\\\"\\n\",\"stream\":\"stdout\",\"time\":\"2017-01-25T14:51:38.65719468Z\"}",
#   "tags" => []
# }
# -----------------------------------------------------------------
#

class LogStash::Filters::KubernetesMetadata < LogStash::Filters::Base

  attr_accessor :lookup_cache

  config_name "kubernetes_metadata"

  # The source field name which contains full path to kubelet log file.
  config :source, :validate => :string, :default => "path"

  # The target field name to write event kubernetes metadata.
  config :target, :validate => :string, :default => "kubernetes"

  # Auth for hitting the Kubernetes API. This can be either basic auth or
  # Bearer auth. It should be formated like the following
  # [source, ruby]
  # -----------------------------------------------------------------
  # auth => { # Authentication for your API in the form of either basic or bearer auth
  #   basic => {
  #     user => "mykubeusername"
  #     pass => "superwonderfulsecurepassword"
  #   }
  #
  #   # ...or...
  #
  #   bearer  => {
  #     key => "mybearerkeystring"
  #   }
  # }
  # -----------------------------------------------------------------
  config :auth, :validate => :hash, :default => {}

  # Kubernetes API URL
  config :api, :validate => :string, :default => "http://127.0.0.1:8001"

  # Default log format
  # This allows you to set a default log format or type for kubernetes logs if not set in the
  # kubernetes metadata annotations.
  # Field kesy in the annotations can be of one following formats:
  #   - log-format-[stdout|stderr]-[container_name]
  #   - log-format-[container_name]
  #   - log-format-[stdout|stderr]
  #   - log-format
  # The format values will be set in the following fields after parsing:
  #   - metadata['log_format_stderr']
  #   - metadata['log_format_stdout']
  # This is completely up to the user to supply and use in their logstash config and will not
  # be used anywhere else
  config :default_log_format, :validate => :string, :default => "default"

  public
  def register
    @logger.debug("Registering Kubernetes Filter plugin")
    self.lookup_cache ||= LruRedux::ThreadSafeCache.new(1000, 900)
    @logger.debug("Created cache...")
  end

  # this is optimized for the single container case. it caches based on filename to avoid the
  # filename munging on every event.

  public
  def filter(event)
    @logger.debug("event is: #{event}")
    path = event.get(@source)

    # Ensure that the path parameter has been defined so that we can find the required metadata
    if (path.nil? || path.empty?)
      event.tag("_kubeparsefailure")
      return
    end

    @logger.debug("Log entry has source field, beginning processing for Kubernetes")

    metadata = {}
    cached_metadata = lookup_cache[path]
    file_metadata = get_file_info(path)

    # If we were unable to extract metadata from the file name, return
    return unless file_metadata

    if cached_metadata
      metadata = file_metadata.merge(cached_metadata)
    else
      @logger.debug("Trying to get kubernetes file info, it was not cached");
      @logger.debug("kubernetes file info got: #{metadata}")

      pod = file_metadata['pod']
      namespace = file_metadata['namespace']
      name = file_metadata['container_name']

      return unless pod and namespace and name

      if data = get_kubernetes(namespace, pod)
        metadata = file_metadata.merge(data)
        set_log_formats(metadata)
        lookup_cache[path] = metadata
      end
      @logger.debug("metadata within lookup_cache[path]: #{metadata}")
    end


    @logger.debug("metadata after unless lookup_cache[path] is: #{metadata}")
    @logger.debug("config after unless lookup_cache[path] is: #{config}")

    event.set(@target, metadata)
    return filter_matched(event)
  end

  def set_log_formats(metadata)
    begin
      #return if metadata['annotations'].empty?

      format = {
        'stderr' => @default_log_format,
        'stdout' => @default_log_format
      }
      a = metadata['annotations']
      n = metadata['container_name']

      # check for log-format-<stream>-<name>, log-format-<name>, log-format-<stream>, log-format
      # in annotations
      %w{ stderr stdout }.each do |t|
        [ "log-format-#{t}-#{n}", "log-format-#{n}", "log-format-#{t}", "log-format" ].each do |k|
          if v = a[k]
            format[t] = v
            break
          end
        end
      end

      metadata['log_format_stderr'] = format['stderr']
      metadata['log_format_stdout'] = format['stdout']
      @logger.debug("kubernetes metadata => #{metadata}")

    rescue => e
      @logger.warn("Error setting log format: #{e}")
    end
  end

  # based on https://github.com/vaijab/logstash-filter-kubernetes/blob/master/lib/logstash/filters/kubernetes.rb
  def get_file_info(path)
    parts = path.split(File::SEPARATOR).last.gsub(/.log$/, '').split('_')
    if parts.length != 3 || parts[2].start_with?('POD-')
      return nil
    end
    kubernetes = {}
    kubernetes['replication_controller'] = parts[0].gsub(/-[0-9a-z]*$/, '')
    kubernetes['pod'] = parts[0]
    kubernetes['namespace'] = parts[1]
    kubernetes['container_name'] = parts[2].gsub(/-[0-9a-z]*$/, '')
    kubernetes['container_id'] = parts[2].split('-').last
    return kubernetes
  end

  def sanatize_keys(data)
    return {} unless data

    parsed_data = {}
    data.each do |k,v|
      new_key = k.gsub(/\.|,/, '_')
        .gsub(/\//, '-')
      parsed_data[new_key] = v
    end

    return parsed_data
  end

  def get_kubernetes(namespace, pod)

    begin
      @logger.debug("Attempting to query the Kubernetes API")

      url = [ @api, 'api/v1/namespaces', namespace, 'pods', pod ].join("/")

      rest_opts = {
        verify_ssl: false
      }

      if @auth
        if @auth['basic']
          @logger.debug("Found basic auth for Kubernetes API")

          basic_user = @auth['basic']['user']
          basic_pass = @auth['basic']['pass']

          rest_opts.merge!( user: basic_user, password: basic_pass )
        end

        if @auth['bearer']
          @logger.debug("Found Bearer  auth for Kubernetes API")

          bearer_key = @auth['bearer']['key']

          rest_opts.merge!( Authorization: "Bearer #{bearer_key}" )
        end
      end

      @logger.debug("rest_opts: #{rest_opts}")

      begin
        response = RestClient::Resource.new(url, rest_opts).get
      rescue RestClient::ResourceNotFound
        @logger.warn("Kubernetes returned an error while querying the API")
        @logger.warn("url: #{url}, rest_opts: #{rest_opts}")
      rescue Exception => e
        @logger.warn("Error while querying the API: #{e.to_s}")
      end

      if response && response.code != 200
        @logger.warn("Non 200 response code returned: #{response.code}")
      end

      @logger.debug("response was: #{response}")

      data = LogStash::Json.load(response.body)

      {
        'annotations' => sanatize_keys(data['metadata']['annotations']),
        'labels' => sanatize_keys(data['metadata']['labels'])
      }
    rescue => e
      @logger.warn("Unknown error while getting Kubernetes metadata: #{e}")
    end
  end
end # class LogStash::Filters::KubernetesMetadata
