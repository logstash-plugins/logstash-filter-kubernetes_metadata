Gem::Specification.new do |s|
  s.name          = 'logstash-filter-kubernetes_metadata'
  s.version       = '1.0.2'
  s.licenses      = ['AGPL-3.0']
  s.summary       = 'Parses kubernetes host and pod metadata from log filename'
  s.homepage      = 'https://github.com/phutchins/logstash-filter-kubernetes_metadata'
  s.authors       = ['Philip Hutchins']
  s.email         = 'flipture@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', '~> 2.0'
  s.add_runtime_dependency 'rest-client', '~> 1.8', '>= 1.8.0'
  s.add_runtime_dependency 'lru_redux', '~> 1.1', '>= 1.1.0'
  s.add_development_dependency 'logstash-devutils'
  s.add_development_dependency 'sinatra'
  s.add_development_dependency 'webrick'
end
