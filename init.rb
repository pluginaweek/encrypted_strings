require 'encrypted_strings'

class ::Integer #:nodoc:
  include PluginAWeek::CoreExtensions::String::EncryptedStrings
end