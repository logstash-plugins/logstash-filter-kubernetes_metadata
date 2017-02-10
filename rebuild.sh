#!/bin/bash

logstash-plugin remove logstash-filter-kubernetes_metadata;
rm ./logstash-filter-kubernetes_metadata-1.0.1.gem;
gem build logstash-filter-kubernetes_metadata.gemspec;
logstash-plugin install ./logstash-filter-kubernetes_metadata-1.0.1.gem
